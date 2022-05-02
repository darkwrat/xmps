#include <stdio.h>
#include <liburing.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <error.h>
#include <assert.h>

#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->f))
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2 * !!(condition)]))

static __s32 xmps_ln_socket(void)
{
	__s32 r, ln, val;

	ln = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
	if (ln < 0) {
		perror("socket-ln");
		return -1;
	}

	val = 1;
	r = setsockopt(ln, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if (r < 0) {
		perror("setsockopt-ln-reuseaddr");
		close(ln);
		return -1;
	}

	val = 1;
	r = setsockopt(ln, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	if (r < 0) {
		perror("setsockopt-ln-nodelay");
		close(ln);
		return -1;
	}

	return ln;
}

static void xmps_ln_dtor(const __s32 *ln) { close(*ln); }

static __s32 xmps_ln_bind(__s32 ln)
{
	struct sockaddr_in addr = {0};
	__s32 r;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(12345);

	r = bind(ln, &addr, sizeof(addr));
	if (r < 0)
		perror("bind-ln");

	return r;
}

static __s32 xmps_ln_listen(__s32 ln)
{
	__s32 r;

	r = listen(ln, SOMAXCONN);
	if (r < 0)
		perror("listen-ln");

	return r;
}

static __s32 xmps_ring_init(struct io_uring *ring)
{
	__s32 r;

	r = io_uring_queue_init(64, ring, 0);
	if (r < 0) {
		error(0, -r, "io_uring_queue_init");
		return -1;
	}

	return 0;
}

static void xmps_ring_dtor(struct io_uring *ring) { io_uring_queue_exit(ring); }

union xmps_sockaddr {
	sa_family_t family;
	struct sockaddr_storage storage;
	struct sockaddr generic;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

struct xmps_addr {
	__u32 len;
	union xmps_sockaddr sockaddr;
};

#define XMPS_OP_PROVIDE_BUFFERS 1
#define XMPS_OP_ACCEPT 2

union xmps_compl {
	__u64 as64;
	struct {
		__u8 op;
		__u16 bid;
		__s16 fda;
		__s16 fdb;
	};
};

#define compl(qe) ((union xmps_compl *)(&(qe)->user_data))

static inline __s8 rtx_dir(struct io_uring_cqe *cqe)
{
	__s8 a = (__s8)(compl(cqe)->fda < 0);
	__s8 b = (__s8)(compl(cqe)->fdb < 0);

	/* -1 means Rx, 1 means Tx, 0 means this cqe is not rtx completion. */
	return (__s8)(a - b);
}

#define BUF_SIZE (16 * 1024 - 1) // 16383 Byte, equals to the max chunk size
#define BUF_COUNT 100
#define BUF_GROUP 0

static __u8 buffers[BUF_COUNT][BUF_SIZE];

static void xmps_ring_make_provide_buffers(struct io_uring *ring, __u16 bid, __s32 count)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_provide_buffers(sqe, &buffers[bid], BUF_SIZE, count, BUF_GROUP, 0);
	compl(sqe)->op = XMPS_OP_PROVIDE_BUFFERS;
}

static void xmps_ring_make_accept(struct io_uring *ring, __s32 ln, struct xmps_addr *addr)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_accept(sqe, ln, &addr->sockaddr.generic, &addr->len, SOCK_CLOEXEC);
	compl(sqe)->op = XMPS_OP_ACCEPT;
}

static void xmps_ring_make_rx(struct io_uring *ring, __s32 fda, __s32 fdb)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_recv(sqe, fda, NULL, BUF_SIZE, 0);
	sqe->buf_group = BUF_GROUP;
	io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
	compl(sqe)->fda = (__s16)fda;
	compl(sqe)->fdb = (__s16)fdb;
}

static void xmps_ring_make_tx(struct io_uring *ring, __s32 fda, __s32 fdb, const void *buf,
			      size_t len)
{
	struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

	io_uring_prep_send(sqe, fdb, buf, len, 0);
	compl(sqe)->fda = (__s16)fda;
	compl(sqe)->fdb = (__s16)fdb;
}

static void xmps_ring_accept(struct io_uring *ring, struct io_uring_cqe *cqe,
			     struct xmps_addr *addr)
{
	if (cqe->res < 0) {
		error(0, -cqe->res, "ring-accept");
		return;
	}

	(void)addr;
	fprintf(stdout, "accepted connection fd %d\n", cqe->res);
	xmps_ring_make_rx(ring, cqe->res, -1);
}

static void xmps_ring_rx(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	__u16 bid = (__u16)(cqe->flags >> 16);

	if (cqe->res < 0) {
		error(0, -cqe->res, "ring-rx");
		return;
	}

	xmps_ring_make_tx(ring, compl(cqe)->fdb, compl(cqe)->fda, &buffers[bid], cqe->res);
	xmps_ring_make_rx(ring, compl(cqe)->fda, compl(cqe)->fdb);
}

static void xmps_ring_tx(struct io_uring *ring, struct io_uring_cqe *cqe)
{
	if (cqe->res < 0) {
		error(0, -cqe->res, "ring-tx");
		return;
	}

	xmps_ring_make_provide_buffers(ring, compl(cqe)->bid, 1);
}

static __attribute__((noreturn)) __s32 xmps_ring_loop(struct io_uring *ring, __s32 ln)
{

	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;
	struct xmps_addr addr;

	sqe = io_uring_get_sqe(ring);
	io_uring_prep_provide_buffers(sqe, buffers, BUF_SIZE, BUF_COUNT, BUF_GROUP, 0);
	compl(sqe)->op = XMPS_OP_PROVIDE_BUFFERS;

	xmps_ring_make_accept(ring, ln, &addr);

	for (;;) {
		__u32 head, count = 0;

		io_uring_submit_and_wait(ring, 1);

		io_uring_for_each_cqe(ring, head, cqe)
		{
			count++;

			if (rtx_dir(cqe) < 0) {
				xmps_ring_rx(ring, cqe);
				continue;
			} else if (rtx_dir(cqe) > 0) {
				xmps_ring_tx(ring, cqe);
				continue;
			}

			switch (compl(cqe)->op) {
			case XMPS_OP_PROVIDE_BUFFERS:
				// todo check cqe->res
				continue;
			case XMPS_OP_ACCEPT:
				xmps_ring_accept(ring, cqe, &addr);
				xmps_ring_make_accept(ring, ln, &addr);
				continue;
			default:
				fprintf(stderr, "unknown op %d\n", (__u32) compl(cqe)->op);
				continue;
			}
		}

		io_uring_cq_advance(ring, count);
	}
}

int main(void)
{
	struct io_uring ring __attribute__((cleanup(xmps_ring_dtor))) = {0};
	__s32 ln __attribute__((cleanup(xmps_ln_dtor))) = -1;

	BUILD_BUG_ON(sizeof(union xmps_compl) != FIELD_SIZEOF(struct io_uring_sqe, user_data));

	if (xmps_ring_init(&ring)) {
		return -1;
	}

	ln = xmps_ln_socket();
	if (ln < 0)
		return -1;

	if (xmps_ln_bind(ln))
		return -1;

	if (xmps_ln_listen(ln))
		return -1;

	xmps_ring_loop(&ring, ln);
}
