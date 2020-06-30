#include "ns3/log.h"
#include "ack-filter.h"
#include "ns3/object-factory.h"
#include "ns3/drop-tail-queue.h"
#include "ns3/header.h"
#include "ns3/ipv4-header.h"
#include "ns3/tcp-header.h"
#include "queue-disc.h"


namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("AckFilter");

NS_OBJECT_ENSURE_REGISTERED (AckFilter);

TypeId AckFilter::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::AckFilter")
    .SetParent<Object> ()
    .SetGroupName ("TrafficControl")
    .AddConstructor<AckFilter> ();
  return tid;
}


AckFilter::AckFilter ()
{
  NS_LOG_FUNCTION (this);
}

AckFilter::~AckFilter ()
{
  NS_LOG_FUNCTION (this);
}

int
AckFilter::AckFilterSackCompare (Ptr<QueueDiscItem> item_a, Ptr<QueueDiscItem> item_b) const
{
  if (item_a->HasTcpOption (TcpOption::SACK) && !(item_b->HasTcpOption (TcpOption::SACK)))
    {
      return -1;
    }
  else if (!(item_a->HasTcpOption (TcpOption::SACK)) && (item_b->HasTcpOption (TcpOption::SACK)))
    {
      return 1;
    }
  else if (!(item_a->HasTcpOption (TcpOption::SACK)) && !(item_b->HasTcpOption (TcpOption::SACK)))
    {
      return 0;
    }
  typedef std::list<std::pair<SequenceNumber32,SequenceNumber32> > sack;
  sack sack_a, sack_b;
  sack_a = item_a->TcpGetSackList ();
  sack_b = item_b->TcpGetSackList ();
  SequenceNumber32 ack_seq_a = item_a->GetAckSeqHeader ();
  uint32_t bytes_a = 0, bytes_b = 0;
  while (true)
    {
      sack sack_temp = sack_b;
      sack::iterator it_a = sack_a.begin ();
      sack::iterator it_b = sack_b.begin ();
      SequenceNumber32 start_a,end_a;
      start_a = it_a->first;
      end_a = it_a->second;
      bool found = false;
      bool first = true;

      if (start_a < ack_seq_a)
        {
          return -1;
        }
      bytes_a += end_a - start_a;
      while (true)
        {
          SequenceNumber32 start_b, end_b;
          start_b = it_b->first;
          end_b = it_b->second;
          if (first)
            {
            }
          bytes_b += end_b - start_b;
          if (!(start_b > start_a) && !(end_b < end_a))
            {
              found = true;
              if (!first)
                {
                  break;
                }
            }
          it_b++;
        }
      if (!found)
        {
          return -1;
        }
      else
        {
          it_a++;
          first = false;
        }
    }
  return bytes_b > bytes_a ? 1 : 0;
}


bool
AckFilter::AckFilterMayDrop (Ptr<QueueDiscItem> item, uint32_t tstamp,uint32_t tsecr) const
{
  uint8_t flags;
  item->GetUint8Value (QueueItem::TCP_FLAGS,flags);
  if (((((flags << 16) & uint32_t (0x0F3F0000)) >> 16) != TcpHeader::ACK) || item->HasTcpOption (TcpOption::SACKPERMITTED) || item->HasTcpOption (TcpOption::WINSCALE) || item->HasTcpOption (TcpOption::UNKNOWN))
    {
      return false;
    }
  else if (item->HasTcpOption (TcpOption::TS))
    {
      uint32_t tstamp_check,tsecr_check;
      item->TcpGetTimestamp (tstamp_check,tsecr_check);
      if ((tstamp_check < tstamp) || (tsecr_check < tsecr))
        {
          return false;
        }
      else
        {
          return true;
        }
    }
  else
    {
      return true;
    }
}

bool
AckFilter::AckFilterMain (Ptr<Queue<QueueDiscItem>> Qu, Ptr<QueueDiscItem> item) const
{

  Ptr<Queue<QueueDiscItem> > queue =  Qu;
  bool hastimestamp;
  uint32_t tstamp, tsecr;
  Ipv4Address src1,src2,dst1,dst2;
  Ipv4Header pk1 , pk2 ;
  Ptr<QueueDiscItem> elig_ack = NULL, elig_ack_prev= NULL;
  uint32_t elig_flags=0;
  int num_found=0;
  Ptr<QueueDiscItem> tail = item;
  
  Ptr<QueueDiscItem> head = *(queue->begin ());
  auto pos = queue->begin();
  
  if(queue->IsEmpty()){
    return false;
  }
   
  if (tail->GetL4Protocol () != 6)
    {
      return false;
    }

  hastimestamp = tail->TcpGetTimestamp (tstamp,tsecr);
  std::cout << hastimestamp << std::endl;
  //the 'triggering' packet need only have the ACK flag set.
  //also check that SYN is not set, as there won't be any previous ACKs.
  uint8_t flags;
  tail->GetUint8Value (QueueItem::TCP_FLAGS,flags);
  if ((flags & (TcpHeader::SYN | TcpHeader::ACK)) != TcpHeader::ACK)
    {
      return false;
    }
  auto prev = queue->begin ();

  //Triggered ack is at tail of the queue we have already returned if it is the only
  //packet in the flow. Loop through the rest of the queue looking for pure ack
  //with the same 5-tuple as the triggered one
 
  for (auto check = queue->begin (); check != queue->end (); prev = check,check++)
    {
      tail->GetSourceL3address (src1);
      tail->GetSourceL3address (src2);
      (*check)->GetDestL3address (dst1);
      tail->GetDestL3address (dst2);
      if(src1!=src2 || dst1!=dst2) {
        continue;
      }
      if ((*check)->GetL4Protocol () != 6 || ((*check)->TcpSourcePort () != tail->TcpSourcePort ()) || ((*check)->TcpDestinationPort () != tail->TcpDestinationPort ()))
        {
          continue;
        }

      Ptr<QueueDiscItem> item = *check;
    
/* Check TCP options and flags, don't drop ACKs with segment
   * data, and don't drop ACKs with a higher cumulative ACK
   * counter than the triggering packet. Check ACK seqno here to
   * avoid parsing SACK options of packets we are going to exclude
   * anyway.
   */
if (!AckFilterMayDrop ( *check,tstamp,tsecr) ||
      (*check)->GetAckSeqHeader ()> tail->GetAckSeqHeader ())
    {
      std::cout<<(*check)->GetAckSeqHeader () << " " << tail->GetAckSeqHeader () << std::endl;
      continue;
    }
   

  /* Check SACK options. The triggering packet must SACK more data
   * than the ACK under consideration, or SACK the same range but
   * have a larger cumulative ACK counter. The latter is a
   * pathological case, but is contained in the following check
   * anyway, just to be safe.
   */
int sack_comp = AckFilterSackCompare(*check, tail);

  if ((sack_comp < 0 ||
      (*check)->GetAckSeqHeader () == tail->GetAckSeqHeader ()) &&
       (sack_comp == 0))
      {
        continue;
      }

  /* At this point we have found an eligible pure ACK to drop; if
   * we are in aggressive mode, we are done. Otherwise, keep
   * searching unless this is the second eligible ACK we
   * found.
   *
   * Since we want to drop ACK closest to the head of the queue,
   * save the first eligible ACK we find, even if we need to loop
   * again.
   */
  if (!elig_ack) {
   
   pos = check;
   elig_ack = *check;
   elig_ack_prev = *prev;
   uint8_t flag_check;
   (*check)->GetUint8Value (QueueItem::TCP_FLAGS,flag_check);
   elig_flags = (flag_check & (TcpHeader::ECE | TcpHeader::CWR));

  }

  if (num_found++ > 0)
  {
   goto found;
  }
 }

 /* We made it through the queue without finding two eligible ACKs . If
  * we found a single eligible ACK we can drop it in aggressive mode if
  * we can guarantee that this does not interfere with ECN flag
  * information. We ensure this by dropping it only if the enqueued
  * packet is consecutive with the eligible ACK, and their flags match.
  */
  uint8_t flag_tail;
      (tail)->GetUint8Value (QueueItem::TCP_FLAGS,flag_tail);
      
  if (elig_ack && (elig_flags == (flag_tail & (TcpHeader::ECE | TcpHeader::CWR))))
  {
     goto found;
  }

found:
 if (elig_ack_prev){
   queue->DoRemove(pos);
   std::cout<<"Removing packet with sequence number " << elig_ack->GetAckSeqHeader() << std::endl;
   return true;
 }

 return false;

 //else
  //flow->head = elig_ack->next;


 //skb_mark_not_on_list(elig_ack);

 //return elig_ack;

}

}
