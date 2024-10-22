#ifndef SOCKMAP_H
#define SOCKMAP_H

struct event
{
    __u32 op;
    __u32 key;
    __u32 value;
};
#endif
