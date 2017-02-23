#include "cachelab.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

typedef enum{false,true} bool;
typedef unsigned long long int addr_t;

typedef struct
{
    char* c_b;//cache_block
    bool v; // valid bit
    addr_t t; // tag bits
    int lru_cnt; // lru replacement count
} cache_line;

typedef struct
{
    cache_line* lines;
} cache_set;

typedef struct
{
    cache_set* sets;
} cache_s;


bool verbose = false;
int s = 0;
int S = 0;
int E = 0;
int b = 0;
int B = 0;
int hit = 0;
int misses = 0;
int evicts = 0;
char* filename = 0;

// print help.
void print_help();

// parsing command.
void command_parsing(int argc, char** argv, int offset);
bool check_args();
cache_s set_cache();
void sim_cache(cache_s cache, addr_t address);
int find_evict_line(cache_set set, int* used_lines);
int find_empty_line(cache_set set);
void free_cache(cache_s cache);
long long bit_pow(int exp);

int main(int argc, char** argv)
{
    if(!strcmp(argv[1],"-h")) print_help();
    else if(!strcmp(argv[1],"-v")) {verbose = true; command_parsing(argc,argv,2);}
    else command_parsing(argc,argv,1);
    char inst;
    addr_t addr;
    int word;
    if(!check_args()) exit(1);

    // long long num_sets = pow(2.0,s);
    // long long block_size = bit_pow(b);
    S = pow(2.0,s);
    B = bit_pow(b);

    cache_s cache;
    cache = set_cache();

    FILE* f=fopen(filename,"r");

    while(fscanf(f," %c %llx,%d\n",&inst,&addr,&word)!=EOF)
    {
        switch(inst)
        {
            case 'I': break;
            case 'L':
            sim_cache(cache,addr);
            break;
            case 'S':
            sim_cache(cache,addr);
            break;
            case 'M':
            sim_cache(cache,addr);
            sim_cache(cache,addr);
            break;
            default:
            break;
        }
    }


    printSummary(hit, misses, evicts);
    free_cache(cache);
    fclose(f);

    return 0;
}


void command_parsing(int argc, char** argv, int offset)
{
    for(int i=offset;i<argc;++i)
    {
        if(!strcmp(argv[i],"-s"))
        {
            ++i;
            s = atoi(argv[i]);
        }
        if(!strcmp(argv[i],"-E"))
        {
            ++i;
            E = atoi(argv[i]);
        }
        if(!strcmp(argv[i],"-b"))
        {
            ++i;
            b = atoi(argv[i]);
        }
        if(!strcmp(argv[i],"-t"))
        {
            ++i;
            filename = argv[i];
        }
    }
}

void print_help()
{
    printf("Usage: ./csim [-hv] -s <num> -E <num> -b <num> -t <file>\n");
    printf("Options:\n");
    printf("-h          Print this help message.\n");
    printf("-v          Optional verbose flag.\n");
    printf("-s <num>    Number of set index bits.\n");
    printf("-E <num>    Number of lines per set.\n");
    printf("-b <num>    Number of block offset bits.\n");
    printf("-t <file>   Trace file.\n\n");
    printf("linux>  ./csim -s 4 -E 1 -b 4 -t traces/yi.trace\n");
    printf("linux>  ./csim -v -s 8 -E 2 -b 4 -t traces/yi.trace\n");
}

bool check_args()
{
    if(s==0||E==0||b==0||filename==0)
        return false;
    return true;
}

cache_s set_cache()
{
    cache_s newCache;
    cache_set set;
    cache_line line;
    int set_index;
    int line_index;

    newCache.sets = (cache_set*) malloc(sizeof(cache_set)*S);

    for(set_index = 0; set_index < S; ++set_index)
    {
        set.lines = (cache_line*) malloc(sizeof(cache_line)*E);
        newCache.sets[set_index] = set;

        for(line_index = 0; line_index<E;++line_index)
        {
            line.lru_cnt = 0;
            line.v = false;
            line.t = 0;
            set.lines[line_index] = line;
        }
    }

    return newCache; 
}

void sim_cache(cache_s cache, addr_t address)
{
    int line_index;
    bool cache_full = true;

    int prev_hits = hit;

    int tag_size = (64-(s+b));
    addr_t input_tag = address >> (s+b);
    unsigned long long temp = address<<(tag_size);
    unsigned long long set_index = temp>>(tag_size+b);

    cache_set current_set = cache.sets[set_index];

    for(line_index = 0; line_index<E; ++line_index)
    {
        cache_line line = current_set.lines[line_index];

        if(line.v&&line.t==input_tag)
        {
            line.lru_cnt++;
            hit++;
            current_set.lines[line_index] = line;
        }
        else if(line.v==false&&cache_full==true) cache_full = false;
        
    }

    if(prev_hits == hit) misses++;
    else return;

    // when miss

    int* used_lines = (int*)malloc(sizeof(int)*2);
    int min_index = find_evict_line(current_set, used_lines);

    if(cache_full)
    {
        evicts++;

        current_set.lines[min_index].t = input_tag;
        current_set.lines[min_index].lru_cnt = used_lines[1]+1;
    }
    else
    {
        int empty_index = find_empty_line(current_set);

        current_set.lines[empty_index].t = input_tag;
        current_set.lines[empty_index].v = true;
        current_set.lines[empty_index].lru_cnt = used_lines[1]+1;
    }
    free(used_lines);
}

int find_evict_line(cache_set set, int* used_lines)
{
    int max = set.lines[0].lru_cnt;
    int min = set.lines[0].lru_cnt;
    int min_index = 0;

    cache_line line;
    int line_index;

    for(line_index = 1 ; line_index<E; ++line_index)
    {
        line = set.lines[line_index];

        if(min>line.lru_cnt){ min = line.lru_cnt; min_index = line_index;}
        if(max<line.lru_cnt) max = line.lru_cnt;
    }

    used_lines[0] = min;
    used_lines[1] = max;

    return min_index;
}
int find_empty_line(cache_set set)
{
    int line_index;
    cache_line line;

    for(line_index = 0;line_index<E;++line_index)
    {
        line = set.lines[line_index];
        if(line.v == false) return line_index;
    }
    return -1;
}

void free_cache(cache_s cache)
{
    int set_index;

    for(set_index=0; set_index<S;++set_index)
    {
        cache_set set = cache.sets[set_index];
        if(set.lines!=NULL) free(set.lines);
    }

    if(cache.sets!=NULL) free(cache.sets);
}

long long bit_pow(int exp) 
{
	long long result = 1;
	result = result << exp;
	return result;
}