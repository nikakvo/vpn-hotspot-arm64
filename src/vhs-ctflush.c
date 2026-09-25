/*
 * vhs-ctflush - drop the conntrack entries of tethered clients.
 *
 * Part of VPN Hotspot Arm64. Android has no "conntrack" tool, and while a
 * client's connections go out directly (module off, or kill switch off with
 * the VPN down) Android's tether offload keeps them alive past the firewall.
 * When the tunnel takes over again those connections must end, so the
 * devices reopen them - through the VPN. Removing a conntrack entry also
 * makes Android's offload drop its fast path for it.
 *
 *   vhs-ctflush [-n] [-k KEEP_IP] CIDR...
 *     CIDR     IPv4 client subnet(s), e.g. 10.41.167.0/24
 *     -k IP    keep entries NATed to IP (connections already in the tunnel)
 *     -n       count only, delete nothing
 *   prints: matched=N deleted=N
 *
 * Plain ctnetlink over a netlink socket, no libraries. Build (static):
 *   zig cc -target aarch64-linux-musl -static -Os -o vhs-ctflush vhs-ctflush.c
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAXNETS 16
#define BUFSZ (64 * 1024)

struct net { uint32_t addr, mask; };
static struct net nets[MAXNETS];
static int nnets;
static uint32_t keep_ip; /* network order, 0 = none */

/* Collected deletions: each is a copy of CTA_TUPLE_ORIG (+ CTA_ZONE) */
static unsigned char *todo;
static size_t todo_len, todo_cap;
static int todo_n;

static int parse_cidr(const char *s, struct net *n) {
	char buf[64];
	int bits = 32;
	struct in_addr a;
	snprintf(buf, sizeof buf, "%s", s);
	char *slash = strchr(buf, '/');
	if (slash) {
		*slash = 0;
		bits = atoi(slash + 1);
		if (bits < 0 || bits > 32) return -1;
	}
	if (inet_pton(AF_INET, buf, &a) != 1) return -1;
	n->mask = bits ? htonl(0xffffffffu << (32 - bits)) : 0;
	n->addr = a.s_addr & n->mask;
	return 0;
}

static int in_nets(uint32_t ip) {
	for (int i = 0; i < nnets; i++)
		if ((ip & nets[i].mask) == nets[i].addr) return 1;
	return 0;
}

/* Find attribute <type> in [p, p+len) (nested flag ignored) */
static struct nlattr *attr_find(void *p, int len, int type) {
	struct nlattr *a = p;
	while (len >= (int)sizeof(*a) && a->nla_len >= sizeof(*a) && a->nla_len <= len) {
		if ((a->nla_type & NLA_TYPE_MASK) == type) return a;
		int step = NLA_ALIGN(a->nla_len);
		len -= step;
		a = (struct nlattr *)((char *)a + step);
	}
	return NULL;
}
#define ATTR_DATA(a) ((void *)((char *)(a) + NLA_HDRLEN))
#define ATTR_LEN(a) ((int)(a)->nla_len - NLA_HDRLEN)

static int tuple_ip(struct nlattr *tuple, int which, uint32_t *out) {
	struct nlattr *ip = attr_find(ATTR_DATA(tuple), ATTR_LEN(tuple), CTA_TUPLE_IP);
	if (!ip) return -1;
	struct nlattr *v = attr_find(ATTR_DATA(ip), ATTR_LEN(ip), which);
	if (!v || ATTR_LEN(v) < 4) return -1;
	memcpy(out, ATTR_DATA(v), 4);
	return 0;
}

static void todo_add(struct nlattr *orig, struct nlattr *zone) {
	size_t need = NLA_ALIGN(orig->nla_len) + (zone ? NLA_ALIGN(zone->nla_len) : 0) + sizeof(uint32_t);
	if (todo_len + need > todo_cap) {
		size_t cap = todo_cap ? todo_cap * 2 : 64 * 1024;
		while (cap < todo_len + need) cap *= 2;
		unsigned char *n = realloc(todo, cap);
		if (!n) return;
		todo = n; todo_cap = cap;
	}
	uint32_t sz = need - sizeof(uint32_t);
	memcpy(todo + todo_len, &sz, sizeof sz);
	unsigned char *d = todo + todo_len + sizeof sz;
	memset(d, 0, sz);
	memcpy(d, orig, orig->nla_len);
	if (zone) memcpy(d + NLA_ALIGN(orig->nla_len), zone, zone->nla_len);
	todo_len += need;
	todo_n++;
}

static int nl_open(void) {
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
	if (fd < 0) return -1;
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(fd); return -1; }
	return fd;
}

static int send_msg(int fd, int type, int flags, const void *payload, size_t plen, uint32_t seq) {
	unsigned char buf[4096];
	struct nlmsghdr *h = (struct nlmsghdr *)buf;
	struct nfgenmsg *g = (struct nfgenmsg *)NLMSG_DATA(h);
	size_t len = NLMSG_LENGTH(sizeof(*g)) + plen;
	if (len > sizeof buf) return -1;
	memset(buf, 0, NLMSG_LENGTH(sizeof(*g)));
	h->nlmsg_len = len;
	h->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | type;
	h->nlmsg_flags = NLM_F_REQUEST | flags;
	h->nlmsg_seq = seq;
	g->nfgen_family = AF_INET;
	g->version = NFNETLINK_V0;
	if (plen) memcpy((char *)g + sizeof(*g), payload, plen);
	struct sockaddr_nl to = { .nl_family = AF_NETLINK };
	return sendto(fd, buf, len, 0, (struct sockaddr *)&to, sizeof to) == (ssize_t)len ? 0 : -1;
}

/* Dump all IPv4 entries, collect the ones to delete. Returns matched count. */
static int dump(int fd) {
	static unsigned char buf[BUFSZ];
	int matched = 0;
	if (send_msg(fd, IPCTNL_MSG_CT_GET, NLM_F_DUMP, NULL, 0, 1) < 0) return -1;
	for (;;) {
		ssize_t n = recv(fd, buf, sizeof buf, 0);
		if (n < 0) { if (errno == EINTR) continue; return -1; }
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)n); h = NLMSG_NEXT(h, n)) {
			if (h->nlmsg_type == NLMSG_DONE) return matched;
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(h);
				if (e->error) { errno = -e->error; return -1; }
				continue;
			}
			int alen = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct nfgenmsg));
			void *attrs = (char *)NLMSG_DATA(h) + NLMSG_ALIGN(sizeof(struct nfgenmsg));
			struct nlattr *orig = attr_find(attrs, alen, CTA_TUPLE_ORIG);
			struct nlattr *reply = attr_find(attrs, alen, CTA_TUPLE_REPLY);
			uint32_t src, rdst;
			if (!orig || tuple_ip(orig, CTA_IP_V4_SRC, &src) < 0 || !in_nets(src)) continue;
			if (keep_ip && reply && tuple_ip(reply, CTA_IP_V4_DST, &rdst) == 0 && rdst == keep_ip) continue;
			matched++;
			todo_add(orig, attr_find(attrs, alen, CTA_ZONE));
		}
	}
}

static int delete_all(int fd) {
	unsigned char ack[4096];
	int deleted = 0;
	uint32_t seq = 100;
	for (size_t off = 0; off < todo_len;) {
		uint32_t sz;
		memcpy(&sz, todo + off, sizeof sz);
		off += sizeof sz;
		if (send_msg(fd, IPCTNL_MSG_CT_DELETE, NLM_F_ACK, todo + off, sz, ++seq) == 0) {
			ssize_t n = recv(fd, ack, sizeof ack, 0);
			if (n > 0) {
				struct nlmsghdr *h = (struct nlmsghdr *)ack;
				if (NLMSG_OK(h, (size_t)n) && h->nlmsg_type == NLMSG_ERROR) {
					struct nlmsgerr *e = NLMSG_DATA(h);
					if (e->error == 0 || e->error == -ENOENT) deleted++; /* ENOENT: already gone */
				}
			}
		}
		off += sz;
	}
	return deleted;
}

int main(int argc, char **argv) {
	int dry = 0, i;
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-n")) dry = 1;
		else if (!strcmp(argv[i], "-k") && i + 1 < argc) {
			struct in_addr a;
			if (inet_pton(AF_INET, argv[++i], &a) != 1) { fprintf(stderr, "bad -k address\n"); return 2; }
			keep_ip = a.s_addr;
		} else if (nnets < MAXNETS && parse_cidr(argv[i], &nets[nnets]) == 0) nnets++;
		else { fprintf(stderr, "usage: vhs-ctflush [-n] [-k KEEP_IP] CIDR...\n"); return 2; }
	}
	if (!nnets) { fprintf(stderr, "usage: vhs-ctflush [-n] [-k KEEP_IP] CIDR...\n"); return 2; }
	int fd = nl_open();
	if (fd < 0) { perror("netlink"); return 1; }
	int matched = dump(fd);
	if (matched < 0) { perror("conntrack dump"); return 1; }
	int deleted = dry ? 0 : delete_all(fd);
	printf("matched=%d deleted=%d\n", matched, deleted);
	close(fd);
	return 0;
}
