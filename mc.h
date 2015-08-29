
#ifndef MC_INCLUDED
#define MC_INCLUDED

/* Number of devices to create */
#ifndef MC_NDEVICES
#define MC_NDEVICES 1    
#endif

/* Size of a buffer used for data storage */
#ifndef MC_BUFFER_SIZE
#define MC_BUFFER_SIZE 1024
#endif

/* Maxumum length of a block that can be read or written in one operation */
#ifndef MC_BLOCK_SIZE
#define MC_BLOCK_SIZE 512
#endif

/* The structure to represent 'mc' devices. 
 *  data - data buffer;
 *  buffer_size - size of the data buffer;
 *  block_size - maximum number of bytes that can be read or written 
 *    in one call;
 *  mc_mutex - a mutex to protect the fields of this structure;
 *  cdev - ñharacter device structure.
 */
struct mc_dev {
        unsigned char *data;
        unsigned long buffer_size; 
        unsigned long block_size;  
        struct mutex mc_mutex; 
        struct cdev cdev;
};

#define SIGNAL_THRESHOLD	0x80000000

#endif /* MC_INCLUDED */