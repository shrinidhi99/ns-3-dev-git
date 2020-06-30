/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2016 Universita' degli Studi di Napoli Federico II
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "ns3/log.h"
#include "ipv4-queue-disc-item.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("Ipv4QueueDiscItem");

Ipv4QueueDiscItem::Ipv4QueueDiscItem (Ptr<Packet> p, const Address& addr,
                                      uint16_t protocol, const Ipv4Header & header)
  : QueueDiscItem (p, addr, protocol),
    m_header (header),
    m_headerAdded (false)
{
}

Ipv4QueueDiscItem::~Ipv4QueueDiscItem ()
{
  NS_LOG_FUNCTION (this);
}

uint32_t Ipv4QueueDiscItem::GetSize (void) const
{
  NS_LOG_FUNCTION (this);
  Ptr<Packet> p = GetPacket ();
  NS_ASSERT (p != 0);
  uint32_t ret = p->GetSize ();
  if (!m_headerAdded)
    {
      ret += m_header.GetSerializedSize ();
    }
  return ret;
}

const Ipv4Header&
Ipv4QueueDiscItem::GetHeader (void) const
{
  return m_header;
}

SequenceNumber32
Ipv4QueueDiscItem::GetAckSeqHeader (void)
{
  TcpHeader tcpHdr;
  GetPacket ()->PeekHeader (tcpHdr);
  return tcpHdr.GetAckNumber ();
}

void Ipv4QueueDiscItem::AddHeader (void)
{
  NS_LOG_FUNCTION (this);

  NS_ASSERT_MSG (!m_headerAdded, "The header has been already added to the packet");
  Ptr<Packet> p = GetPacket ();
  NS_ASSERT (p != 0);
  p->AddHeader (m_header);
  m_headerAdded = true;
}

void
Ipv4QueueDiscItem::Print (std::ostream& os) const
{
  if (!m_headerAdded)
    {
      os << m_header << " ";
    }
  os << GetPacket () << " "
     << "Dst addr " << GetAddress () << " "
     << "proto " << (uint16_t) GetProtocol () << " "
     << "txq " << (uint8_t) GetTxQueueIndex ()
  ;
}

bool
Ipv4QueueDiscItem::Mark (void)
{
  NS_LOG_FUNCTION (this);
  if (!m_headerAdded && m_header.GetEcn () != Ipv4Header::ECN_NotECT)
    {
      m_header.SetEcn (Ipv4Header::ECN_CE);
      return true;
    }
  return false;
}


bool
Ipv4QueueDiscItem::GetUint8Value (QueueItem::Uint8Values field, uint8_t& value) const
{
  bool ret = false;

  switch (field)
    {
    case IP_DSFIELD:
      value = m_header.GetTos ();
      ret = true;
      break;
    case TCP_FLAGS:
      uint8_t prot = m_header.GetProtocol ();
      if (prot == 6)
        {
          TcpHeader tcpHdr;
          GetPacket ()->PeekHeader (tcpHdr);
          value = tcpHdr.GetFlags ();
          ret = true;
        }
      else
        {
          ret = false;
        }
    }

  return ret;
}

uint32_t
Ipv4QueueDiscItem::Hash (uint32_t perturbation) const
{
  NS_LOG_FUNCTION (this << perturbation);

  Ipv4Address src = m_header.GetSource ();
  Ipv4Address dest = m_header.GetDestination ();
  uint8_t prot = m_header.GetProtocol ();
  uint16_t fragOffset = m_header.GetFragmentOffset ();

  TcpHeader tcpHdr;
  UdpHeader udpHdr;
  uint16_t srcPort = 0;
  uint16_t destPort = 0;

  if (prot == 6 && fragOffset == 0) // TCP
    {
      GetPacket ()->PeekHeader (tcpHdr);
      srcPort = tcpHdr.GetSourcePort ();
      destPort = tcpHdr.GetDestinationPort ();
    }
  else if (prot == 17 && fragOffset == 0) // UDP
    {
      GetPacket ()->PeekHeader (udpHdr);
      srcPort = udpHdr.GetSourcePort ();
      destPort = udpHdr.GetDestinationPort ();
    }
  if (prot != 6 && prot != 17)
    {
      NS_LOG_WARN ("Unknown transport protocol, no port number included in hash computation");
    }

  /* serialize the 5-tuple and the perturbation in buf */
  uint8_t buf[17];
  src.Serialize (buf);
  dest.Serialize (buf + 4);
  buf[8] = prot;
  buf[9] = (srcPort >> 8) & 0xff;
  buf[10] = srcPort & 0xff;
  buf[11] = (destPort >> 8) & 0xff;
  buf[12] = destPort & 0xff;
  buf[13] = (perturbation >> 24) & 0xff;
  buf[14] = (perturbation >> 16) & 0xff;
  buf[15] = (perturbation >> 8) & 0xff;
  buf[16] = perturbation & 0xff;

  // Linux calculates jhash2 (jenkins hash), we calculate murmur3 because it is
  // already available in ns-3
  uint32_t hash = Hash32 ((char*) buf, 17);

  NS_LOG_DEBUG ("Hash value " << hash);

  return hash;
}

uint16_t
Ipv4QueueDiscItem::TcpSourcePort (void)
{
  TcpHeader tcpHdr;
  GetPacket ()->PeekHeader (tcpHdr);
  return tcpHdr.GetSourcePort ();
}

uint16_t
Ipv4QueueDiscItem::TcpDestinationPort (void)
{
  TcpHeader tcpHdr;
  GetPacket ()->PeekHeader (tcpHdr);
  return tcpHdr.GetDestinationPort ();
}

Ipv4QueueDiscItem::SackList
Ipv4QueueDiscItem::TcpGetSackList (void)
{
  TcpHeader tcpHdr;
  GetPacket ()->PeekHeader (tcpHdr);
  Ptr<const TcpOptionSack> s = DynamicCast<const TcpOptionSack> (tcpHdr.GetOption (TcpOption::SACK));
  TcpOptionSack::SackList list = s->GetSackList ();
  return list;
}

bool
Ipv4QueueDiscItem::TcpGetTimestamp (uint32_t &tstamp,uint32_t &tsecr)
{
  TcpHeader tcpHdr;
  GetPacket ()->PeekHeader (tcpHdr);
  if (tcpHdr.HasOption (TcpOption::TS))
    {
      Ptr<const TcpOptionTS> ts = DynamicCast<const TcpOptionTS> (tcpHdr.GetOption (TcpOption::TS));
      tstamp = ts->GetTimestamp ();
      tsecr = ts->GetEcho ();
      return true;
    }
  else
    {
      return false;
    }
}

uint8_t
Ipv4QueueDiscItem::GetL4Protocol (void)
{
  uint8_t prot = m_header.GetProtocol ();
  return prot;
}

void
Ipv4QueueDiscItem::GetSourceL3address (Ipv4Address &src)
{
  src = m_header.GetSource ();
}

void
Ipv4QueueDiscItem::GetDestL3address (Ipv4Address &Dest)
{
  Dest = m_header.GetDestination ();
}

bool
Ipv4QueueDiscItem::HasTcpOption (uint8_t kind)
{
  TcpHeader tcpHdr;
  GetPacket ()->PeekHeader (tcpHdr);
  return tcpHdr.HasOption (kind);
}
} // namespace ns3
