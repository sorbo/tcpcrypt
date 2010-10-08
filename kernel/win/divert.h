#ifndef __DIVERT_H__
#define __DIVERT_H__

int divert_filter(
   IN PADAPT         pAdapt,
   IN NDIS_HANDLE    MacReceiveContext,
   IN PVOID          HeaderBuffer,
   IN UINT           HeaderBufferSize,
   IN PVOID          LookAheadBuffer,
   IN UINT           LookAheadBufferSize,
   IN UINT           PacketSize
   );

int divert_filter_send(PADAPT pAdapt, PNDIS_PACKET Packet, int in);

NTSTATUS divert_read(
    IN PDEVICE_OBJECT       pDeviceObject,
    IN PIRP                 pIrp
    );

NTSTATUS
divert_write(
    IN PDEVICE_OBJECT       pDeviceObject,
    IN PIRP                 pIrp
    );

int divert_send_complete(PNDIS_PACKET Pkt);

void divert_init(void);
void divert_kill(void);
void divert_bind(PADAPT adapt);
void divert_open(void);
void divert_close(void);
int divert_req_complete(PADAPT adapt, PNDIS_REQUEST req);

#endif // __DIVERT_H__
