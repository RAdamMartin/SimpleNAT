
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int sr_nat_init(struct sr_nat *nat,
                unsigned int icmp_timeout,
                unsigned int tcp_est_timeout,
                unsigned int tcp_trans_timeout) {

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  /* Initialize any variables here */
  nat->icmp_to = icmp_timeout;
  nat->tcp_est_to = tcp_est_timeout;
  nat->tcp_trans_to = tcp_trans_timeout;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    /* handle periodic tasks here */
    struct sr_nat_mapping *maps = nat->mappings;
    struct sr_nat_mapping *prev = NULL;
    while(maps != NULL){ /*TODO: SEND ICMP??*/
      double diff = difftime(curtime, maps->last_updated);
        
      if (maps->type == nat_mapping_icmp && diff > nat->icmp_to){
        if(prev == NULL){
          nat->mappings = NULL;
        } else {
          prev->next = maps->next;
        }
        free(maps);
      }/*TODO IP Timeouts*/
    }
    

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *maps = nat->mappings;
  while(maps != NULL){
    if (maps->aux_ext == aux_ext && type == maps->type){
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy,maps,sizeof(struct sr_nat_mapping));
      return copy;
    }
    copy = copy->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *maps = nat->mappings;
  while(maps != NULL){
    if (maps->ip_int == ip_int && maps->aux_int == aux_int && type == maps->type){
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy,maps,sizeof(struct sr_nat_mapping));
      return copy;
    }
    copy = copy->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  mapping = malloc(sizeof(struct sr_nat_mapping));
  mapping->ip_int = ip_int;
  /*mapping->ip_ext = ??*/
  mapping->aux_int = aux_int;
  /*mapping->aux_ext ? TODO*/
  mapping->last_updated = time(NULL);
  mapping->next = nat->mappings;
  
  nat->mappings = mapping;
  struct sr_nat_mapping *ret_map = malloc(sizeof(struct sr_nat_mapping));
  memcpy(ret_map,mapping,sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return ret_map;
}
