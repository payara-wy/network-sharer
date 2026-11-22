#ifndef NETWORKSHARER_STANDALONE_LEASES_H
#define NETWORKSHARER_STANDALONE_LEASES_H
#include <libslirp.h>
struct lease_store;
/* Directory must already exist, be owned by the effective user and private.
 * A single writer is enforced. Missing state is accepted; corrupt state fails. */
struct lease_store *lease_open(const char *directory,Slirp *slirp);
int lease_commit(struct lease_store *store,Slirp *slirp);
void lease_close(struct lease_store *store);
#endif
