#include "precomp.h"
#pragma hdrstop

#define QUEUE_SIZE 64

struct divert_packet {
	int	      		dp_len;
	unsigned char		dp_packet[2048];
	int			dp_flags;
	struct divert_packet	*dp_next;
};

static struct divert_packet _packet_queue, _packet_free;
static NDIS_SPIN_LOCK _lock;
static PIRP _pending;
static NDIS_HANDLE _packet_pool, _buf_pool;
static PADAPT _pa;
static unsigned char _mac[NPROT_MAC_ADDR_LEN];
static int _open;

static void lock(void)
{
	NdisAcquireSpinLock(&_lock);
}

static void unlock(void)
{
	NdisReleaseSpinLock(&_lock);
}

void divert_init(void)
{
	int i;
	struct divert_packet *dp;
	NDIS_STATUS status;

	for (i = 0; i < QUEUE_SIZE; i++) {
		dp = ExAllocatePoolWithTag(PagedPool, sizeof(*dp),
					   (ULONG) "ao");

		if (!dp)
			DbgPrint("ExAllocatePoolWithTag()");

		memset(dp, 0, sizeof(*dp));

		dp->dp_next = _packet_free.dp_next;
		_packet_free.dp_next = dp;
	}

	NdisAllocateSpinLock(&_lock);

	NdisAllocateBufferPool(&status, &_buf_pool, QUEUE_SIZE);
	NdisAllocatePacketPool(&status, &_packet_pool, QUEUE_SIZE, 16);
}

static void free_queue(struct divert_packet *dp)
{
	dp = dp->dp_next;

	while (dp) {
		struct divert_packet *tmp = dp->dp_next;

		ExFreePoolWithTag(dp, (ULONG) "ao");

		dp = tmp;
	}
}

void divert_kill(void)
{
	lock();

	free_queue(&_packet_queue);
	free_queue(&_packet_free);

	// XXX
	NdisFreeBufferPool(_buf_pool);
	NdisFreePacketPool(_packet_pool);

	unlock();

	NdisFreeSpinLock(&_lock);
}

static void divert_do_recv(PIRP Irp)
{
	struct divert_packet *dp;
	PUCHAR                      currentAddress;

	currentAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress,
						      NormalPagePriority);

	dp = _packet_queue.dp_next;

	_packet_queue.dp_next = dp->dp_next;

	dp->dp_next = _packet_free.dp_next;
	_packet_free.dp_next = dp;

	if (dp->dp_flags) {
		RtlMoveMemory(currentAddress, dp->dp_packet, dp->dp_len);
		Irp->IoStatus.Information = dp->dp_len;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static struct divert_packet *get_packet(void)
{
	struct divert_packet *dp, *cur;

	dp = _packet_free.dp_next;

	if (!dp)
		return NULL;

	_packet_free.dp_next = dp->dp_next;

	// XXX
	cur = &_packet_queue;
	while (cur->dp_next)
		cur = cur->dp_next;

	cur->dp_next = dp;
	dp->dp_next  = NULL;

	return dp;
}

static void kick_pending(void)
{
	if (_pending) {
		PIRP Irp = _pending;

		_pending = NULL;

		if (IoSetCancelRoutine(Irp, NULL))
			divert_do_recv(Irp);
	}
}

int divert_filter_send(PADAPT pAdapt, PNDIS_PACKET Packet)
{
#define HDR_SIZE 54
	int len, cnt;
	PNDIS_BUFFER buf;
	char crap[HDR_SIZE];
	int rc = 0, rd;
	struct ether_header  *pEthHdr;      // See ../B2Winet/ethernet.h
	struct ip            *pIPHeader;
	struct tcphdr	     *tcp;
	struct divert_packet *dp;
	int off = 0; // 14;

	NdisAcquireSpinLock(&pAdapt->Lock);

	NdisQueryPacket(Packet, NULL, &cnt, &buf, &len);

	if (len < HDR_SIZE)
		goto Out;

	FltReadOnPacket(Packet, crap, HDR_SIZE, 0, &rd);
	if (rd < HDR_SIZE)
		goto Out;

	pEthHdr = (struct ether_header*) crap;

	if (ntohs( pEthHdr->ether_type ) != ETHERTYPE_IP)
		goto Out;

	pIPHeader = (struct ip * ) (pEthHdr + 1);
	tcp	  = (struct tcphr*) (pIPHeader + 1);

#if 0
	if (ntohs(tcp->th_dport) == 666)
		rc = 1;
#endif

	lock();

	if (!_open)
		goto Fuck;

	dp = get_packet();
	if (!dp) {
		DbgPrint("divert_packet() - outta space dude\n");
		goto Fuck;
	}

	dp->dp_len = len - off;
	FltReadOnPacket(Packet, dp->dp_packet, dp->dp_len, off, &rd);
//	rd = dp->dp_len;
	if (rd != dp->dp_len)
		goto Fuck;

	dp->dp_flags = 1;

	kick_pending();

	rc = 1;

Fuck:
	unlock();
Out:
	NdisReleaseSpinLock(&pAdapt->Lock);

	return rc;
#undef HDR_SIZE
}

int divert_filter(
   IN PADAPT         pAdapt,
   IN NDIS_HANDLE    MacReceiveContext,
   IN PVOID          HeaderBuffer,
   IN UINT           HeaderBufferSize,
   IN PVOID          LookAheadBuffer,
   IN UINT           LookAheadBufferSize,
   IN UINT           PacketSize
   )
{
#define MAC_SIZE 14
	USHORT               EtherType;
	ULONG                NumberOfBytesRead;
	struct ether_header  *pEthHdr;      // See ../B2Winet/ethernet.h
	struct ip            *pIPHeader;
	struct tcphdr	     *tcp;
	int rc = 0;
	struct divert_packet *dp, *cur;
	NDISPROT_ETH_HEADER UNALIGNED *pEthHeader;

	NdisDprAcquireSpinLock(&pAdapt->Lock);

	pEthHdr = (struct ether_header * )HeaderBuffer;
	pEthHeader = pEthHdr;

	if (ntohs( pEthHdr->ether_type ) != ETHERTYPE_IP)
		goto Out;

	if (NPROT_MEM_CMP(pEthHeader->SrcAddr, _mac, NPROT_MAC_ADDR_LEN))
		goto Out;

	pIPHeader = (struct ip * )LookAheadBuffer;

	if (LookAheadBufferSize < 40)
		goto Out;

	tcp = (struct tcphr*) (pIPHeader + 1);

#if 0
	if (ntohs(tcp->th_dport) == 666)
		rc = 1;
#endif

	lock();

	if (!_open)
		goto Outl;

	dp = get_packet();
	if (!dp) {
		DbgPrint("Out of queue - shit\n");
		goto Outl;
	}

	if (LookAheadBufferSize != PacketSize) {
		NDIS_STATUS status;
		PNDIS_PACKET pkt;
		PNDIS_BUFFER buf;
		int len;

		if ((PacketSize + MAC_SIZE) > sizeof(dp->dp_packet)) {
			DbgPrint("cAZZOOOOOOOOOOOOOOOOOOOOOOOOOOo\n");
			goto Fanculo;
		}

		NdisAllocatePacket(&status, &pkt, _packet_pool);
		NdisAllocateBuffer(&status, &buf, _buf_pool,
				   dp->dp_packet + MAC_SIZE,
				   sizeof(dp->dp_packet) - MAC_SIZE);
		NdisChainBufferAtFront(pkt, buf);
		NdisTransferData(&status, pAdapt->BindingHandle,
				 MacReceiveContext, 0,
				 PacketSize, pkt, &len);
		NdisFreeBuffer(buf);
		NdisFreePacket(pkt);
	} else {
		NdisCopyLookaheadData(dp->dp_packet + MAC_SIZE,
				      LookAheadBuffer,
				      LookAheadBufferSize,
				      0);
	}

Fanculo:
	rc = 1;

	memcpy(dp->dp_packet, pEthHdr, MAC_SIZE);

	dp->dp_len   = PacketSize + MAC_SIZE;
	dp->dp_flags = 1;

	kick_pending();

Outl:
	unlock();
Out:
	NdisDprReleaseSpinLock(&pAdapt->Lock);

	return rc;
#undef MAC_SIZE
}

VOID
divert_read_cancel(
    IN PDEVICE_OBJECT               pDeviceObject,
    IN PIRP                         pIrp
    )
{
	PIRP p;	

	IoReleaseCancelSpinLock(pIrp->CancelIrql);

	lock();
	p = _pending;
	unlock();

	if (p != pIrp)
		return;

        pIrp->IoStatus.Status = STATUS_CANCELLED;
        pIrp->IoStatus.Information = 0;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
}

NTSTATUS
divert_read(
    IN PDEVICE_OBJECT       pDeviceObject,
    IN PIRP                 Irp
    )
{
	PIO_STACK_LOCATION          irpStack;
	NTSTATUS		    rc = STATUS_SUCCESS;
	struct divert_packet *dp;

	irpStack = IoGetCurrentIrpStackLocation(Irp);

	if (Irp->MdlAddress == NULL) {
		DbgPrint("fuck\n");

		rc = STATUS_INVALID_PARAMETER;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);

		return rc;
	}


/*
	DbgPrint("Addr %p\n", currentAddress);
	

	DbgPrint("AO %d %d\n",
		 irpStack->Parameters.Read.ByteOffset.LowPart,
		 irpStack->Parameters.Read.Length);

         RtlMoveMemory(currentAddress,
         driverExtension->buffer+irpStack->Parameters.Read.ByteOffset.LowPart,
         irpStack->Parameters.Read.Length);
*/

	lock();

	dp = _packet_queue.dp_next;

	if (!dp) {
		if (_pending)
			DbgPrint("pending already set!");

		_pending = Irp;

		IoMarkIrpPending(Irp);
		IoSetCancelRoutine(Irp, divert_read_cancel);

		unlock();

		return STATUS_PENDING;
	}

	rc = STATUS_SUCCESS;

	divert_do_recv(Irp);

	unlock();

	return rc;
}

NTSTATUS
divert_write(
    IN PDEVICE_OBJECT       pDeviceObject,
    IN PIRP                 pIrp
    )
{
	int rc = STATUS_SUCCESS;
	PNDIS_PACKET pNdisPacket;
	PADAPT pa = _pa; // XXX
	NDIS_STATUS status;
	PIO_STACK_LOCATION pIrpSp;
	NDISPROT_ETH_HEADER UNALIGNED *pEthHeader;

	pIrpSp = IoGetCurrentIrpStackLocation(pIrp);

	if (pIrp->MdlAddress == NULL) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		goto Out;
	}

	if (!(pEthHeader = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress,
					  		NormalPagePriority))) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		goto Out;
	}

	lock();

	NdisAllocatePacket(&status, &pNdisPacket, _packet_pool);

	unlock();

	if (status != STATUS_SUCCESS) {
		rc = STATUS_INSUFFICIENT_RESOURCES;
		goto Out;
	}

	NdisChainBufferAtFront(pNdisPacket, pIrp->MdlAddress);

	if (NPROT_MEM_CMP(pEthHeader->SrcAddr, _mac, NPROT_MAC_ADDR_LEN)) {
		NdisSendPackets(pa->BindingHandle, &pNdisPacket, 1);
	} else {
		NDIS_SET_PACKET_STATUS(pNdisPacket, NDIS_STATUS_RESOURCES);
		NdisMIndicateReceivePacket(pa->MiniportHandle, &pNdisPacket, 1);
		NdisFreePacket(pNdisPacket);
	}

	rc = STATUS_PENDING;
	rc = STATUS_SUCCESS;

Out:
	pIrp->IoStatus.Status = rc;

	if (rc != STATUS_PENDING) {
		pIrp->IoStatus.Information = pIrpSp->Parameters.Write.Length;
        	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}

	return rc;
}

int divert_send_complete(PNDIS_PACKET Pkt)
{
	int rc = 0;

	lock();

	if (NdisGetPoolFromPacket(Pkt) == _packet_pool) {
		NdisFreePacket(Pkt);
		rc = 1;
	}

	unlock();

	return rc;
}

NDIS_REQUEST _req;

// XXX this whole thing is fucked up
static void get_mac(PADAPT adapt)
{
    NDIS_STATUS                 Status;

    _req.RequestType = NdisRequestQueryInformation;
    _req.DATA.QUERY_INFORMATION.Oid = OID_802_3_CURRENT_ADDRESS;
    _req.DATA.QUERY_INFORMATION.InformationBuffer = _mac;
    _req.DATA.QUERY_INFORMATION.InformationBufferLength = NPROT_MAC_ADDR_LEN;

    NdisRequest(&Status,
                adapt->BindingHandle,
                &_req);
   
    if (Status == NDIS_STATUS_PENDING) {
		DbgPrint("fUCK PENDING\n");

		while (_req.DATA.QUERY_INFORMATION.Oid != 0)
			NdisMSleep(2);

    } else {
		_req.DATA.QUERY_INFORMATION.Oid = 0;
    		DbgPrint("MAC %x %x %x %x %x %x\n",
			 _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);
    }
}

int divert_req_complete(PADAPT adapt, PNDIS_REQUEST req)
{
	if (_req.DATA.QUERY_INFORMATION.Oid == OID_802_3_CURRENT_ADDRESS
            && req->DATA.QUERY_INFORMATION.Oid == OID_802_3_CURRENT_ADDRESS) {
		_req.DATA.QUERY_INFORMATION.Oid = 0;

    		DbgPrint("MAC after waiting %x %x %x %x %x %x\n",
			 _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);	
		return 1;
	}

	return 0;
}

void divert_bind(PADAPT adapt)
{
	_pa = adapt; // XXX

    	get_mac(adapt);
}

void divert_open(void)
{
	lock();

	_open++;

	DbgPrint("Open %d\n", _open);

	unlock();
}

void divert_close(void)
{
	lock();

	_open--;

	DbgPrint("Close %d\n", _open);

	unlock();
}
