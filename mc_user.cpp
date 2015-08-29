#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>

static int debug_flag = 0;

unsigned long directWrite(unsigned long addr, unsigned long data)
{
    if (spi_io(spi_fd, 0, addr, &data, sizeof(data), 0) < 0){					  
		return -1;
	}
   return 0;
}

void spartanWrite(unsigned long addr, unsigned long data)
{
   addr += SPARTAN_OFFSET;
   int stat = directWrite(addr, data);
}

void reset_FLINK_cmd_fifo(void){
	// reset the FLINK1 RX fifos in the FPGA to clear old data
	spartanWrite(WREG_FLINK1_RX_FIFO_RESET, 1);
	spartanWrite(WREG_FLINK1_RX_FIFO_RESET, 0);
}

void reset_FLINK_sts_fifo(void){
	// reset the FLINK2 RX fifos in the FPGA to clear old data
	spartanWrite(WREG_FLINK2_RX_FIFO_RESET, 1);
	spartanWrite(WREG_FLINK2_RX_FIFO_RESET, 0);
}

int main ( int argc, char ** argv )
{	
	int err = 0;
	int tmp;
	struct timeval timeout;
	fd_set readset, writeset, exset;
	
	if (getenv("MLED_DEBUG")){
		debug_flag = 1;
	}
	
	if (argc>1){
		led_test = atoi(argv[1]);
		printf("led_test=%d",led_test);
	}
	
	spi_fd = spi_init("/dev/spidev1.1", 1000000);
	if (spi_fd < 0) {
		printf("Error open spi driver\n");
		return -1;	
	}
	
	int fd = open ("/dev/mc0", O_RDWR);
	if (fd < 0) {
		printf("Error open mc driver\n");
		return -1;
	}

	FD_ZERO(&readset);
	FD_SET(fd, &readset);
	FD_ZERO(&writeset);
	FD_SET(fd, &writeset);	
	FD_ZERO(&exset);
	FD_SET(fd, &exset);

	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

/*	
	system("/home/sitara/bin/mem 0x48032034 0x80000000");		//GPIO_GPIO_IRQSTATUS_SET_0, pin 31
	system("/home/sitara/bin/mem 0x4803214C 0x80000000");  		//GPIO_FALLINGDETECT, pin 31
*/	
	
	reset_FLINK_cmd_fifo();
	reset_FLINK_sts_fifo();	
	
	//enable command and status interrupts
	flink_interrupt_enable_cmd_rx(true);
 	flink_interrupt_enable_sts_rx(true);	
	
	while(1){	
		err = select(FD_SETSIZE, &readset, &writeset, &exset, NULL);
		if (err == 0) {
			printf("select error\n");
			break;
		}	
		else if(FD_ISSET(fd,&readset)){
			//err = read(fd,&tmp,sizeof(int));
			if (debug_flag) printf("user space interrupt response\n");
			bool trig;
			flink_interrupt_is_triggered_cmd_rx(&trig);
			if (trig){
				if (debug_flag) printf("triggered by command\n");
                
				// If we don't care about Flink, just reset the RX fifo
				reset_FLINK_cmd_fifo();				
				
				flink_interrupt_acknowledge_cmd_rx(); 
			}
			flink_interrupt_is_triggered_sts_rx(&trig);
			if (trig){
				if (debug_flag) printf("triggered by status\n");

				// If we don't care about Flink, just reset the RX fifo
				reset_FLINK_sts_fifo();			
				
				flink_interrupt_acknowledge_sts_rx(); 
			}			
		}
	}
	
	close (fd);
	if (spi_fd > 0) {
		close(spi_fd);
	}	
    return 0;
}

// FLink functions

static void flink_interrupt_enable(bool enable, unsigned bit)
{
	unsigned long cur_val;
   	if (spi_io(spi_fd, 1, RREG_FLINK_INTERRUPT_CFG, &cur_val, sizeof(cur_val), 0) < 0){					  
		return;
	}
	if (enable) {
	  cur_val |= (1 << bit);
	} else {
	  cur_val &= ~(1 << bit);
	}
    if (spi_io(spi_fd, 0, RREG_FLINK_INTERRUPT_CFG, &cur_val, sizeof(cur_val), 0) < 0){					  
		return;
	} 
}

static bool flink_interrupt_is_triggered(unsigned bit)
{
	unsigned long status_reg;
   	if (spi_io(spi_fd, 1, RREG_FLINK_INTERRUPT_STATUS, &status_reg, sizeof(status_reg), 0) < 0){					  
		return false;
	}	  
	return (status_reg & (1 << bit));
}

static void flink_interrupt_acknowledge(unsigned bit)
{
    unsigned long cur_val = 1 << bit;
   	if (spi_io(spi_fd, 0, WREG_FLINK_INTERRUPT_ACK, &cur_val, sizeof(cur_val), 0) < 0){					  
		return;
	}
}

static void flink_interrupt_simulate(unsigned bit)
{
    unsigned long cur_val = 1 << bit;
   	if (spi_io(spi_fd, 0, WREG_FLINK_INTERRUPT_TEST, &cur_val, sizeof(cur_val), 0) < 0){					  
		return;
	}    
}

int flink_interrupt_enable_cmd_rx(bool enable)
{
   const unsigned bit = 0;
   flink_interrupt_enable(enable, bit);
   return 0;
}

int flink_interrupt_enable_sts_rx(bool enable)
{
   const unsigned bit = 1;
   flink_interrupt_enable(enable, bit);
   return 0;
}

int flink_interrupt_is_triggered_cmd_rx(bool *triggered)
{
   const unsigned bit = 0;
   bool trig = flink_interrupt_is_triggered(bit);
   if (triggered) {
      *triggered = trig;
   }
   return 0;
}

int flink_interrupt_is_triggered_sts_rx(bool *triggered)
{
   const unsigned bit = 1;
   bool trig = flink_interrupt_is_triggered(bit);
   if (triggered) {
      *triggered = trig;
   }
   return 0;
}

int flink_interrupt_acknowledge_cmd_rx(void)
{
   const unsigned bit = 0;
   flink_interrupt_acknowledge(bit);
   return 0;
}

int flink_interrupt_acknowledge_sts_rx(void)
{
   const unsigned bit = 1;
   flink_interrupt_acknowledge(bit);
   return 0;
}

int flink_interrupt_simulate_cmd_rx(void)
{
   const unsigned bit = 0;
   flink_interrupt_simulate(bit);
   return 0;
}

int flink_interrupt_simulate_sts_rx(void)
{
   const unsigned bit = 1;
   flink_interrupt_simulate(bit);
   return 0;
}