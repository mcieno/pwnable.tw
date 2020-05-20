// gcc -m32 -c -g structs.c -o structs.o
struct Note_t
{
    void (*printer)(struct Note_t *);
    char *content;
};

struct Note_t note;
