#ifndef __CONFIG_H__
#define __CONFIG_H__
// If your PC has VT-D installed, turn this feature
#define ENABLED_IOMMU				0
/*
 * Kernel patch workaround is experimental feature. If you want to use code
 * patch workaround, turn on this feature.
 */
#define ENABLED_WORKAROUND		    0

/* These features should be set. */
#define ENABLED_EPT				    1
#define ENABLED_UNRESTRICTED		1
#define ENABLED_HW_BREAKPOINT		1
#define ENABLED_DESC_TABLE		    1
#define ENABLED_PRE_SYMBOL		    1

#define ENABLED_STAROZA             1 //Play the witcher to understand the name

#if ENABLED_STAROZA
#define ENABLED_PRE_TIMER			0
#else
#define ENABLED_PRE_TIMER			1
#endif

#endif // __CONFIG_H__