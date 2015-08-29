#include <linux/version.h>
#include <linux/err.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/delay.h>	/* udelay */
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/poll.h>
#include <linux/wait.h>
#include <linux/gpio.h>
#include <linux/irq.h>
#include <asm/io.h>
#include <asm/signal.h>
#include <asm/uaccess.h>
#include <asm/siginfo.h>	//siginfo
#include <linux/rcupdate.h>	//rcu_read_lock
#include <linux/debugfs.h>
//#include <linux/uaccess.h>
//#include <linux/pid.h>
#include "mc.h"


MODULE_AUTHOR ("fcao");
MODULE_LICENSE("GPL");

#define MC_DEVICE_NAME "mc"

static int mc_ndevices = MC_NDEVICES;
static unsigned long mc_buffer_size = MC_BUFFER_SIZE;
static unsigned long mc_block_size = MC_BLOCK_SIZE;

module_param(mc_ndevices, int, S_IRUGO);
module_param(mc_buffer_size, ulong, S_IRUGO);
module_param(mc_block_size, ulong, S_IRUGO);

static unsigned int mc_major = 0;
static struct mc_dev *mc_devices = NULL;
static struct class *mc_class = NULL;

static struct work_struct mc_wq;
static unsigned long mc_wq_count = 0;
static unsigned long savecount = 0;
static DECLARE_WAIT_QUEUE_HEAD(mc_queue);
static int mc_poll_flag = 0;

unsigned long mc_base = 0;
#define m_READ				0
#define m_WRITE				1

#define GPIO_PIN	31
static int irq_num;

#define SIG_TEST 44	// we choose 44 as our signal number (real-time signals are in the range of 33 to 64)
static int user_process_pid;

ssize_t signal_module_write_pid(struct file *file, const char __user *buf, size_t count, loff_t *ppos)								
{
	char mybuf[10];
	int pid = 0;
	/* read the value from user space */
	if(count > 10)
		return -EINVAL;
	copy_from_user(mybuf, buf, count);
	sscanf(mybuf, "%d", &pid);
	printk(KERN_WARNING "pid = %d\n", pid);
	user_process_pid = pid;
	return count;
}

void send_signal(unsigned long arg){	
	int ret;
	struct siginfo info;
	struct task_struct *t;
	/* send the signal */
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIG_TEST;
	info.si_code = SI_QUEUE;	// this is bit of a trickery: SI_QUEUE is normally used by sigqueue from user space,
					// and kernel space should use SI_KERNEL. But if SI_KERNEL is used the real_time data 
					// is not delivered to the user space signal handler function. 
	info.si_int = arg;  		//real time signals may have 32 bits of data.

	rcu_read_lock();
//	t = find_task_by_pid_type(PIDTYPE_PID, pid);  //find the task_struct associated with this pid
	t = pid_task(find_pid_ns(user_process_pid, &init_pid_ns), PIDTYPE_PID);	
	if(t == NULL){
		printk(KERN_WARNING "no such pid\n");
		rcu_read_unlock();
		return -ENODEV;
	}
	rcu_read_unlock();
	ret = send_sig_info(SIG_TEST, &info, t);    //send the signal
	if (ret < 0) {
		printk("error sending signal\n");
		return ret;
	}
	return ret;
}

int mc_open (struct inode *inode, struct file *filp)
{
	unsigned int mj = imajor(inode);
	unsigned int mn = iminor(inode);
	
	struct mc_dev *dev = NULL;
	
	if (mj != mc_major || mn < 0 || mn >= mc_ndevices)
	{
			printk(KERN_WARNING "[target] "
					"No device found with minor=%d and major=%d\n", 
					mj, mn);
			return -ENODEV; /* No such device */
	}
	
	/* store a pointer to struct mc_dev here for other methods */
	dev = &mc_devices[mn];
	filp->private_data = dev; 
	
	if (inode->i_cdev != &dev->cdev)
	{
			printk(KERN_WARNING "[target] open: internal error\n");
			return -ENODEV; /* No such device */
	}
	
	/* if opened the 1st time, allocate the buffer */
	if (dev->data == NULL)
	{
		dev->data = (unsigned char*)kzalloc(dev->buffer_size, GFP_KERNEL);
		if (dev->data == NULL)
		{
				printk(KERN_WARNING "[target] open(): out of memory\n");
				return -ENOMEM;
		}
	}
	return 0;
}

int mc_release (struct inode *inode, struct file *filp)
{
	return 0;
}

ssize_t mc_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
	struct mc_dev *dev = (struct mc_dev *)filp->private_data;
	ssize_t retval = 0;
		
	if (mutex_lock_killable(&dev->mc_mutex))
			return -EINTR;
	
	if (*f_pos >= dev->buffer_size) /* EOF */
			goto out;
	
	if (*f_pos + count > dev->buffer_size)
			count = dev->buffer_size - *f_pos;
	
	if (count > dev->block_size)
			count = dev->block_size;
			
	if (copy_to_user(buf, &(dev->data[*f_pos]), count) != 0)
	{
			retval = -EFAULT;
			goto out;
	}	
	
	*f_pos += count;
	retval = count;
	
out:
	mutex_unlock(&dev->mc_mutex);
	return retval;
}
                                
ssize_t mc_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
	struct mc_dev *dev = (struct mc_dev *)filp->private_data;
	ssize_t retval = 0;
	
	if (mutex_lock_killable(&dev->mc_mutex))
			return -EINTR;
	
	signal_module_write_pid(filp, buf, count, f_pos);
	
	if (*f_pos >= dev->buffer_size) {
	/* Writing beyond the end of the buffer is not allowed. */
			retval = -EINVAL;
			goto out;
	}
	
	if (*f_pos + count > dev->buffer_size)
			count = dev->buffer_size - *f_pos;
	
	if (count > dev->block_size)
			count = dev->block_size;
	
	if (copy_from_user(&(dev->data[*f_pos]), buf, count) != 0)
	{
			retval = -EFAULT;
			goto out;
	}
	
	*f_pos += count;
	retval = count;
	
out:
	mutex_unlock(&dev->mc_mutex);
	return retval;
}

loff_t mc_llseek(struct file *filp, loff_t off, int whence)
{
	struct mc_dev *dev = (struct mc_dev *)filp->private_data;
	loff_t newpos = 0;
	
	switch(whence) {
	  case 0: /* SEEK_SET */
			newpos = off;
			break;

	  case 1: /* SEEK_CUR */
			newpos = filp->f_pos + off;
			break;

	  case 2: /* SEEK_END */
			newpos = dev->buffer_size + off;
			break;

	  default: /* can't happen */
			return -EINVAL;
	}
	if (newpos < 0 || newpos > dev->buffer_size) 
			return -EINVAL;
	
	filp->f_pos = newpos;
	return newpos;
}

static int mc_ioctl(struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg)
{

	unsigned long result = 0; 
	
	switch(cmd) {

	  case m_READ:
			mc_base = arg; 
			break;				
			
	  case m_WRITE:
			mc_base = arg;			
			break;
			
	  default:  /* redundant, as cmd was checked against MAXNR */
			return -EINVAL;
	}
	
	return 0;
}

unsigned int mc_poll(struct file *filp, poll_table *wait)
{
	struct mc_dev *dev = filp->private_data;
	unsigned int mask = 0;
	if (mutex_lock_killable(&dev->mc_mutex))
			return -EINTR;			
	poll_wait(filp, &mc_queue,  wait);			
	if (mc_poll_flag){			
		mask = POLLIN | POLLRDNORM;
		mc_poll_flag = 0;
	}
	mutex_unlock(&dev->mc_mutex);
	return mask;
}

void mc_do_workqueue(unsigned long arg)
{
	savecount = mc_wq_count;
	mc_poll_flag = 1;
	wake_up_interruptible(&mc_queue); /* awake any reading process */		
	//send_signal(savecount | SIGNAL_THRESHOLD);
}

irqreturn_t mc_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	if ((mc_wq_count+1) >= SIGNAL_THRESHOLD){
		mc_wq_count = 0;
	}
	mc_wq_count++;
	//printk("mc_handler %d\n",mc_wq_count);
	//send_signal(mc_wq_count);
	schedule_work(&mc_wq);	
    return IRQ_HANDLED;
}

struct file_operations mc_fops = {
	.owner	 = THIS_MODULE,
	.read	 = mc_read,
	.write	 = mc_write,
	.llseek =   mc_llseek,
	.poll	 = mc_poll,
	.open	 = mc_open,
	.unlocked_ioctl	 = mc_ioctl,
	.release = mc_release,
};

/* ================================================================ */
/* Setup and register the device with specific index (the index is also
 * the minor number of the device).
 * Device class should be created beforehand.
 */
static int mc_construct_device(struct mc_dev *dev, int minor, struct class *class)
{
	int err = 0;
	dev_t devno = MKDEV(mc_major, minor);
	struct device *device = NULL;
	
	BUG_ON(dev == NULL || class == NULL);

	/* Memory is to be allocated when the device is opened the first time */
	dev->data = NULL;     
	dev->buffer_size = mc_buffer_size;
	dev->block_size = mc_block_size;
	mutex_init(&dev->mc_mutex);
	
	cdev_init(&dev->cdev, &mc_fops);
	dev->cdev.owner = THIS_MODULE;
	
	err = cdev_add(&dev->cdev, devno, 1);
	if (err)
	{
			printk(KERN_WARNING "[target] Error %d while trying to add %s%d",
					err, MLED_DEVICE_NAME, minor);
			return err;
	}

	device = device_create(class, NULL, /* no parent device */ 
			devno, NULL, /* no additional data */
			MLED_DEVICE_NAME "%d", minor);

	if (IS_ERR(device)) {
			err = PTR_ERR(device);
			printk(KERN_WARNING "[target] Error %d while trying to create %s%d",
					err, MLED_DEVICE_NAME, minor);
			cdev_del(&dev->cdev);
			return err;
	}
	return 0;
}

/* Destroy the device and free its buffer */
static void mc_destroy_device(struct mc_dev *dev, int minor, struct class *class)
{
        BUG_ON(dev == NULL || class == NULL);
        device_destroy(class, MKDEV(mc_major, minor));
        cdev_del(&dev->cdev);
        kfree(dev->data);
        mutex_destroy(&dev->mc_mutex);
        return;
}

static void mc_cleanup_module(int devices_to_destroy)
{
        int i;
        
        /* Get rid of character devices (if any exist) */
        if (mc_devices) {
			for (i = 0; i < devices_to_destroy; ++i) {
					mc_destroy_device(&mc_devices[i], i, mc_class);
			}
			kfree(mc_devices);
        }
        
        if (mc_class)
                class_destroy(mc_class);

        /* [NB] mc_cleanup_module is never called if alloc_chrdev_region()
         * has failed. */
        unregister_chrdev_region(MKDEV(mc_major, 0), mc_ndevices);
        return;
}

static int __init mc_init(void)
{
	int err = 0;
	int i = 0;
	int devices_to_destroy = 0;
	dev_t dev = 0;
	
	if (mc_ndevices <= 0)
	{
			printk(KERN_WARNING "[target] Invalid value of mc_ndevices: %d\n", 
					mc_ndevices);
			err = -EINVAL;
			return err;
	}
	
	/* Get a range of minor numbers (starting with 0) to work with */
	err = alloc_chrdev_region(&dev, 0, mc_ndevices, MLED_DEVICE_NAME);
	if (err < 0) {
			printk(KERN_WARNING "[target] alloc_chrdev_region() failed\n");
			return err;
	}
	mc_major = MAJOR(dev);

	/* Create device class (before allocation of the array of devices) */
	mc_class = class_create(THIS_MODULE, MLED_DEVICE_NAME);
	if (IS_ERR(mc_class)) {
		err = PTR_ERR(mc_class);
		goto fail;
	}
	
	/* Allocate the array of devices */
	mc_devices = (struct mc_dev *)kzalloc(
			mc_ndevices * sizeof(struct mc_dev), 
			GFP_KERNEL);
	if (mc_devices == NULL) {
			err = -ENOMEM;
			goto fail;
	}
	
	/* Construct devices */
	for (i = 0; i < mc_ndevices; ++i) {
			err = mc_construct_device(&mc_devices[i], i, mc_class);
			if (err) {
				devices_to_destroy = i;
				goto fail;
			}
	}
	
	INIT_WORK(&mc_wq, (void (*)(void *)) mc_do_workqueue);
	
	irq_num = gpio_to_irq(GPIO_PIN);
	err = request_irq(irq_num, mc_handler, 0, "mc", NULL);
	if (err) {
		printk("can't get assigned irq %i\n",irq_num);
		goto fail;
	}
	
	set_irq_type(irq_num, IRQ_TYPE_EDGE_FALLING);
	//set_irq_type(irq_num, IRQ_TYPE_LEVEL_LOW);	
	
	return 0; /* success */

fail:
	mc_cleanup_module(devices_to_destroy);
	return err;
}

static void __exit mc_exit(void)
{
	printk("released\n");
    mc_cleanup_module(mc_ndevices);
	free_irq(irq_num, NULL);
	gpio_free(GPIO_PIN);
	return;	
}

module_init(mc_init);
module_exit(mc_exit);
