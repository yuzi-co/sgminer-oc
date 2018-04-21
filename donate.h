#ifndef DONATE_H
#define DONATE_H

/*
 * Minimum dev donation.
 * Minimum percentage of your hashing power that you want to donate to the
 * developer, can be 0 if you prefer not to.
 * You can set the donation percentage higher by using the --donate flag.
 *
 * Example of how it works for the default setting of 1:
 * You miner will mine into your usual pool for 99 minutes, then switch to the
 * developer's pool for 1 minute.
  */
#define MIN_DEV_DONATE_PERCENT 2


// 60 minutes
#define DONATE_CYCLE_TIME 3600

#endif
