/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019 NITK Surathkal
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
 *
 * Ported to ns-3 by: Vignesh Kannan <vignesh2496@gmail.com>
 *                    Harsh Lara <harshapplefan@gmail.com>
 *                    Jendaipou Palmei <jendaipoupalmei@gmail.com>
 *                    Shefali Gupta <shefaligups11@gmail.com>
 *                    Mohit P. Tahiliani <tahiliani@nitk.edu.in>
 */

#include "ns3/test.h"
#include "ns3/cobalt-queue-disc.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/string.h"
#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/queue.h"
#include "ns3/ipv4-queue-disc-item.h"


using namespace ns3;
/**
 * \ingroup traffic-control-test
 * \ingroup tests
 *
 * \brief Cobalt Queue Disc Test Item
 */
class CobaltQueueDiscTestItem : public QueueDiscItem
{
public:
  /**
   * Constructor
   *
   * \param p packet
   * \param addr address
   * \param protocol
   */

  CobaltQueueDiscTestItem (Ptr<Packet> p, const Address & addr,uint16_t protocol, bool ecnCapable);
  virtual ~CobaltQueueDiscTestItem ();
  virtual void AddHeader (void);
  virtual bool Mark (void);

private:
  CobaltQueueDiscTestItem ();
  /**
   * \brief Copy constructor
   * Disable default implementation to avoid misuse
   */
  CobaltQueueDiscTestItem (const CobaltQueueDiscTestItem &);
  /**
   * \brief Assignment operator
   * \return this object
   * Disable default implementation to avoid misuse
   */
  CobaltQueueDiscTestItem &operator = (const CobaltQueueDiscTestItem &);
  bool m_ecnCapablePacket; ///< ECN capable packet?
};

CobaltQueueDiscTestItem::CobaltQueueDiscTestItem (Ptr<Packet> p, const Address & addr,uint16_t protocol, bool ecnCapable)
  : QueueDiscItem (p, addr, ecnCapable),
    m_ecnCapablePacket (ecnCapable)
{
}

CobaltQueueDiscTestItem::~CobaltQueueDiscTestItem ()
{
}

void
CobaltQueueDiscTestItem::AddHeader (void)
{
}

bool
CobaltQueueDiscTestItem::Mark (void)
{
  if (m_ecnCapablePacket)
    {
      return true;
    }
  return false;
}

/**
 * \ingroup traffic-control-test
 * \ingroup tests
 *
 * \brief Test 1: simple enqueue/dequeue with no drops
 */
class CobaltQueueDiscBasicEnqueueDequeue : public TestCase
{
public:
  /**
   * Constructor
   *
   * \param mode the mode
   */
  CobaltQueueDiscBasicEnqueueDequeue (QueueSizeUnit mode);
  virtual void DoRun (void);

  /**
   * Queue test size function
   * \param queue the queue disc
   * \param size the size
   * \param error the error string
   *
   */

private:
  QueueSizeUnit m_mode; ///< mode
};

CobaltQueueDiscBasicEnqueueDequeue::CobaltQueueDiscBasicEnqueueDequeue (QueueSizeUnit mode)
  : TestCase ("Basic enqueue and dequeue operations, and attribute setting" + std::to_string (mode))
{
  m_mode = mode;
}

void
CobaltQueueDiscBasicEnqueueDequeue::DoRun (void)
{
  Ptr<CobaltQueueDisc> queue = CreateObject<CobaltQueueDisc> ();

  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;

  Address dest;

  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MinBytes", UintegerValue (pktSize)), true,
                         "Verify that we can actually set the attribute MinBytes");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue ("50ms")), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue ("4ms")), true,
                         "Verify that we can actually set the attribute Target");

  if (m_mode == QueueSizeUnit::BYTES)
    {
      modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
      modeSize = 1;
    }
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 1500))),
                         true, "Verify that we can actually set the attribute MaxSize");
  queue->Initialize ();

  Ptr<Packet> p1, p2, p3, p4, p5, p6;
  p1 = Create<Packet> (pktSize);
  p2 = Create<Packet> (pktSize);
  p3 = Create<Packet> (pktSize);
  p4 = Create<Packet> (pktSize);
  p5 = Create<Packet> (pktSize);
  p6 = Create<Packet> (pktSize);

  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 0 * modeSize, "There should be no packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p1, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 2 * modeSize, "There should be two packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p3, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 3 * modeSize, "There should be three packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p4, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 4 * modeSize, "There should be four packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p5, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 5 * modeSize, "There should be five packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p6, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 6 * modeSize, "There should be six packets in queue");

  NS_TEST_EXPECT_MSG_EQ (queue->GetStats ().GetNDroppedPackets (CobaltQueueDisc::OVERLIMIT_DROP), 0, "There should be no packets being dropped due to full queue");

  Ptr<QueueDiscItem> item;

  item = queue->Dequeue ();
  NS_TEST_EXPECT_MSG_EQ ((item != 0), true, "I want to remove the first packet");
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 5 * modeSize, "There should be five packets in queue");
  NS_TEST_EXPECT_MSG_EQ (item->GetPacket ()->GetUid (), p1->GetUid (), "was this the first packet ?");

  item = queue->Dequeue ();
  NS_TEST_EXPECT_MSG_EQ ((item != 0), true, "I want to remove the second packet");
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 4 * modeSize, "There should be four packets in queue");
  NS_TEST_EXPECT_MSG_EQ (item->GetPacket ()->GetUid (), p2->GetUid (), "Was this the second packet ?");

  item = queue->Dequeue ();
  NS_TEST_EXPECT_MSG_EQ ((item != 0), true, "I want to remove the third packet");
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 3 * modeSize, "There should be three packets in queue");
  NS_TEST_EXPECT_MSG_EQ (item->GetPacket ()->GetUid (), p3->GetUid (), "Was this the third packet ?");

  item = queue->Dequeue ();
  NS_TEST_EXPECT_MSG_EQ ((item != 0), true, "I want to remove the forth packet");
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 2 * modeSize, "There should be two packets in queue");
  NS_TEST_EXPECT_MSG_EQ (item->GetPacket ()->GetUid (), p4->GetUid (), "Was this the fourth packet ?");

  item = queue->Dequeue ();
  NS_TEST_EXPECT_MSG_EQ ((item != 0), true, "I want to remove the fifth packet");
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue");
  NS_TEST_EXPECT_MSG_EQ (item->GetPacket ()->GetUid (), p5->GetUid (), "Was this the fifth packet ?");

  item = queue->Dequeue ();
  NS_TEST_EXPECT_MSG_EQ ((item != 0), true, "I want to remove the last packet");
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 0 * modeSize, "There should be zero packet in queue");
  NS_TEST_EXPECT_MSG_EQ (item->GetPacket ()->GetUid (), p6->GetUid (), "Was this the sixth packet ?");

  item = queue->Dequeue ();
  NS_TEST_EXPECT_MSG_EQ ((item == 0), true, "There are really no packets in queue");

  NS_TEST_EXPECT_MSG_EQ (queue->GetStats ().GetNDroppedPackets (CobaltQueueDisc::TARGET_EXCEEDED_DROP), 0, "There should be no packet drops according to Cobalt algorithm");
}

/**
 * \ingroup traffic-control-test
 * \ingroup tests
 *
 * \brief Test 2: Cobalt Queue Disc Drop Test Item
 */
class CobaltQueueDiscDropTest : public TestCase
{
public:
  CobaltQueueDiscDropTest ();
  virtual void DoRun (void);
  /**
   * Enqueue function
   * \param queue the queue disc
   * \param size the size
   * \param nPkt the number of packets
   */
  void Enqueue (Ptr<CobaltQueueDisc> queue, uint32_t size, uint32_t nPkt);
  /**
   * Run Cobalt test function
   * \param mode the mode
   */
  void RunDropTest (QueueSizeUnit mode);

  void EnqueueWithDelay (Ptr<CobaltQueueDisc> queue, uint32_t size, uint32_t nPkt);

};

CobaltQueueDiscDropTest::CobaltQueueDiscDropTest ()
  : TestCase ("Drop tests verification for both packets and bytes mode")
{
}

void
CobaltQueueDiscDropTest::RunDropTest (QueueSizeUnit mode)

{
  uint32_t pktSize = 1500;
  uint32_t modeSize = 0;
  Ptr<CobaltQueueDisc> queue = CreateObject<CobaltQueueDisc> ();

  if (mode == QueueSizeUnit::BYTES)
    {
      modeSize = pktSize;
    }
  else if (mode == QueueSizeUnit::PACKETS)
    {
      modeSize = 1;
    }

  queue = CreateObject<CobaltQueueDisc> ();
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (mode, modeSize * 100))),
                         true, "Verify that we can actually set the attribute MaxSize");

  queue->Initialize ();

  if (mode == QueueSizeUnit::BYTES)
    {
      EnqueueWithDelay (queue, pktSize, 200);
    }
  else
    {
      EnqueueWithDelay (queue, 1, 200);
    }

  Simulator::Stop (Seconds (8.0));
  Simulator::Run ();

  QueueDisc::Stats st = queue->GetStats ();

// The Pdrop value should increase, from it's default value of zero
  NS_TEST_EXPECT_MSG_NE (queue->GetPdrop (), 0, "Pdrop should be non-zero");
  NS_TEST_EXPECT_MSG_NE (st.GetNDroppedPackets (CobaltQueueDisc::OVERLIMIT_DROP), 0, "Drops due to queue overflow should be non-zero");
}

void
CobaltQueueDiscDropTest::EnqueueWithDelay (Ptr<CobaltQueueDisc> queue, uint32_t size, uint32_t nPkt)
{
  Address dest;
  double delay = 0.01;  // enqueue packets with delay
  for (uint32_t i = 0; i < nPkt; i++)
    {
      Simulator::Schedule (Time (Seconds ((i + 1) * delay)), &CobaltQueueDiscDropTest::Enqueue, this, queue, size, 1);
    }
}

void
CobaltQueueDiscDropTest::Enqueue (Ptr<CobaltQueueDisc> queue, uint32_t size, uint32_t nPkt)
{
  Address dest;
  for (uint32_t i = 0; i < nPkt; i++)
    {
      queue->Enqueue (Create<CobaltQueueDiscTestItem> (Create<Packet> (size), dest, 0, true));
    }
}

void
CobaltQueueDiscDropTest::DoRun (void)
{
  RunDropTest (QueueSizeUnit::PACKETS);
  RunDropTest (QueueSizeUnit::BYTES);
  Simulator::Destroy ();
}

/*
	This test is designed to verify the functionality of TCP ACK Filter. We
enqueued first a TCP packet with ACK enabled and some sequence number and
then we enqueued one TCP Packet with SYN, ACK Flag enabled and higher
sequence number. No packet will be dropped because packet at the Tail has SYN
flag enabled and dropping this packet may result in loss of information at TCP
sender side.

--Avakash 
*/
class CobaltBasicSynAckTest : public TestCase
{
public:
  /**
   * Constructor
   *
   * \param mode the mode
   */
  CobaltBasicSynAckTest (QueueSizeUnit mode);
  virtual void DoRun (void);

  /**
   * Queue test size function
   * \param queue the queue disc
   * \param size the size
   * \param error the error string
   *
   */

private:
  QueueSizeUnit m_mode; ///< mode
};

CobaltBasicSynAckTest::CobaltBasicSynAckTest (QueueSizeUnit mode)
  : TestCase ("Basic enqueue and dequeue operations with ack filtering, and attribute setting" + std::to_string (mode))
{
  m_mode = mode;
}

void
CobaltBasicSynAckTest::DoRun (void)
{
  Ptr<CobaltQueueDisc> queue = CreateObject<CobaltQueueDisc> ();

  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;

  Address dest;

  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MinBytes", UintegerValue (pktSize)), true,
                         "Verify that we can actually set the attribute MinBytes");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue ("50ms")), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue ("4ms")), true,
                         "Verify that we can actually set the attribute Target");

  if (m_mode == QueueSizeUnit::BYTES)
    {
      modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
      modeSize = 1;
    }
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 1500))),
                         true, "Verify that we can actually set the attribute MaxSize");
  queue->Initialize ();
  TcpHeader tcpHdr;
  uint8_t flags =TcpHeader::SYN;
  tcpHdr.SetFlags (flags);

  Ptr<Packet> p1, p2;
  p1 = Create<Packet> (pktSize);
  p1->AddHeader(tcpHdr);
  flags|=TcpHeader::ACK;
  p2 = Create<Packet> (pktSize);
  p2->AddHeader(tcpHdr);

  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 0 * modeSize, "There should be no packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p1, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 2 * modeSize, "There should be two packet in queue");
  }

  /**
   * This is Test Case 1 : Enqueue UDP Packets and check if they are getting dropped
   * No packets should be dropped as Ack Filtering is only for TCP Packets.
   */

class AckFilterUdpEnqueueTest : public TestCase
{
public:
  /**
   * Constructor
   *
   * \param mode the mode
   */
  AckFilterUdpEnqueueTest (QueueSizeUnit mode);
  virtual void DoRun (void);

  /**
   * Queue test size function
   * \param queue the queue disc
   * \param size the size
   * \param error the error string
   *
   */

private:
  QueueSizeUnit m_mode; ///< mode
};

AckFilterUdpEnqueueTest::AckFilterUdpEnqueueTest (QueueSizeUnit mode)
  : TestCase ("Basic enqueue operations of UDP Packets with ack filtering, and attribute setting" + std::to_string (mode))
{
  m_mode = mode;
}

void
AckFilterUdpEnqueueTest::DoRun (void)
{
  Ptr<CobaltQueueDisc> queue = CreateObject<CobaltQueueDisc> ();

  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;

  Address dest;

  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MinBytes", UintegerValue (pktSize)), true,
                         "Verify that we can actually set the attribute MinBytes");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue ("50ms")), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue ("4ms")), true,
                         "Verify that we can actually set the attribute Target");

  if (m_mode == QueueSizeUnit::BYTES)
    {
      modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
      modeSize = 1;
    }
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 1500))),
                         true, "Verify that we can actually set the attribute MaxSize");
  queue->Initialize ();

  UdpHeader udpHdr;

  Ptr<Packet> p1, p2;
  p1 = Create<Packet> (pktSize);
  p1->AddHeader(udpHdr);
  p2 = Create<Packet> (pktSize);
  p2->AddHeader(udpHdr);


  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 0 * modeSize, "There should be no packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p1, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 2 * modeSize, "There should be two packet in queue, two packets means it wasnt dropped");
  }


  /**
   * This is Test Case 4 : Enqueue pkt with ece, cwr flag and then check that it's being dropped
   * because of another ack (also with ece, cwr) of higher number.
   */

class AckFilterEceCwrFlagTest : public TestCase
{
public:
  /**
   * Constructor
   *
   * \param mode the mode
   */
  AckFilterEceCwrFlagTest (QueueSizeUnit mode);
  void AddPacket(Ptr<Packet> p,Ptr<CobaltQueueDisc> queue, Ipv4Header hdr);
  virtual void DoRun (void);

  /**
   * Queue test size function
   * \param queue the queue disc
   * \param size the size
   * \param error the error string
   *
   */

private:
  QueueSizeUnit m_mode; ///< mode
};

AckFilterEceCwrFlagTest::AckFilterEceCwrFlagTest (QueueSizeUnit mode)
  : TestCase ("ECE, CWR Flag enabled packets check with ack filtering, and attribute setting" + std::to_string (mode))
{
  m_mode = mode;
}

void
AckFilterEceCwrFlagTest::AddPacket (Ptr<Packet> p, Ptr<CobaltQueueDisc> queue, Ipv4Header hdr)
{
  // Ptr<Packet> p = Create<Packet> (100);
  Address dest;
  Ptr<Ipv4QueueDiscItem> item = Create<Ipv4QueueDiscItem> (p, dest, 0, hdr);
  queue->Enqueue (item);
}

void
AckFilterEceCwrFlagTest::DoRun (void)
{
  Ptr<CobaltQueueDisc> queue = CreateObjectWithAttributes<CobaltQueueDisc> ("UseAckFilter", BooleanValue (true));

  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;

  Address dest;

  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MinBytes", UintegerValue (pktSize)), true,
                         "Verify that we can actually set the attribute MinBytes");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue ("50ms")), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue ("4ms")), true,
                         "Verify that we can actually set the attribute Target");

  if (m_mode == QueueSizeUnit::BYTES)
    {
      modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
      modeSize = 1;
    }
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 1500))),
                         true, "Verify that we can actually set the attribute MaxSize");
  queue->Initialize ();

  TcpHeader tcpHdr1;
  // uint8_t flags1 =TcpHeader::ACK|TcpHeader::ECE|TcpHeader::CWR;
  tcpHdr1.SetFlags (TcpHeader::ACK|TcpHeader::ECE|TcpHeader::CWR);
  SequenceNumber32 num1 (1);
  tcpHdr1.SetAckNumber (num1);
  tcpHdr1.SetSourcePort(22);
  tcpHdr1.SetDestinationPort(25);

  TcpHeader tcpHdr2;
  // uint8_t flags2 =TcpHeader::ACK|TcpHeader::ECE|TcpHeader::CWR;
  tcpHdr2.SetFlags (TcpHeader::ACK|TcpHeader::ECE|TcpHeader::CWR);
  SequenceNumber32 num2 (1501);
  tcpHdr2.SetAckNumber (num2);
  tcpHdr2.SetSourcePort(22);
  tcpHdr2.SetDestinationPort(25);

  Ptr<Packet> p1, p2;
  p1 = Create<Packet> (pktSize);
  p1->AddHeader(tcpHdr1);
  p2 = Create<Packet> (pktSize);
  p2->AddHeader(tcpHdr2);

  Ipv4Header hdr;
  hdr.SetPayloadSize (100);
  hdr.SetSource (Ipv4Address ("10.10.1.1"));
  hdr.SetDestination (Ipv4Address ("10.10.1.2"));
  hdr.SetProtocol (6);

  Ipv4Header hdr1;
  hdr1.SetPayloadSize (100);
  hdr1.SetSource (Ipv4Address ("10.10.1.2"));
  hdr1.SetDestination (Ipv4Address ("10.10.1.3"));
  hdr1.SetProtocol (6);

  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 0 * modeSize, "There should be no packets in queue");
  // queue->Enqueue (Create<CobaltQueueDiscTestItem> (p1, dest,0, false));
  AddPacket (p1, queue, hdr);
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue");
  // queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest,0, false));
  AddPacket (p2, queue, hdr);
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue, the first packet was dropped");
  }


  /**
   * This is Test Case 5 : Enqueue pkt with ece, cwr flag and SACK_PERMITTED enabled. Then check that it isn't being dropped
   * because of another ack (also with ece, cwr) of higher number.
   */

class AckFilterSackPermittedTest : public TestCase
{
public:
  /**
   * Constructor
   *
   * \param mode the mode
   */
  AckFilterSackPermittedTest (QueueSizeUnit mode);
  virtual void DoRun (void);

  /**
   * Queue test size function
   * \param queue the queue disc
   * \param size the size
   * \param error the error string
   *
   */

private:
  QueueSizeUnit m_mode; ///< mode
};

AckFilterSackPermittedTest::AckFilterSackPermittedTest (QueueSizeUnit mode)
  : TestCase ("ECE, CWR Flag and SACK_PERMITTED enabled packets check with ack filtering, and attribute setting" + std::to_string (mode))
{
  m_mode = mode;
}

void
AckFilterSackPermittedTest::DoRun (void)
{
  Ptr<CobaltQueueDisc> queue = CreateObject<CobaltQueueDisc> ();

  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;

  Address dest;

  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MinBytes", UintegerValue (pktSize)), true,
                         "Verify that we can actually set the attribute MinBytes");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue ("50ms")), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue ("4ms")), true,
                         "Verify that we can actually set the attribute Target");

  if (m_mode == QueueSizeUnit::BYTES)
    {
      modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
      modeSize = 1;
    }
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 1500))),
                         true, "Verify that we can actually set the attribute MaxSize");
  queue->Initialize ();

  TcpHeader tcpHdr1;
  uint8_t flags1 =TcpHeader::ACK|TcpHeader::ECE|TcpHeader::CWR;
  tcpHdr1.SetFlags (flags1);
  SequenceNumber32 num1 (1);
  tcpHdr1.SetAckNumber (num1);
  tcpHdr1.AppendOption(TcpOption::CreateOption(TcpOption::SACKPERMITTED));

  TcpHeader tcpHdr2;
  uint8_t flags2 =TcpHeader::ACK|TcpHeader::ECE|TcpHeader::CWR;
  tcpHdr2.SetFlags (flags2);
  SequenceNumber32 num2 (1501);
  tcpHdr2.SetAckNumber (num2);

  Ptr<Packet> p1, p2;
  p1 = Create<Packet> (pktSize);
  p1->AddHeader(tcpHdr1);
  p2 = Create<Packet> (pktSize);
  p2->AddHeader(tcpHdr2);


  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 0 * modeSize, "There should be no packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p1, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 2 * modeSize, "There should be two packets in queue, the first packet was not dropped");
  }


  /**
   * This is Test Case 7 : Enqueue pkt with urg flag and then check if its being dropped
   * because of another ack of higher number.
   */

class AckFilterUrgFlagTest : public TestCase
{
public:
  /**
   * Constructor
   *
   * \param mode the mode
   */
  AckFilterUrgFlagTest (QueueSizeUnit mode);
  virtual void DoRun (void);

  /**
   * Queue test size function
   * \param queue the queue disc
   * \param size the size
   * \param error the error string
   *
   */

private:
  QueueSizeUnit m_mode; ///< mode
};

AckFilterUrgFlagTest::AckFilterUrgFlagTest (QueueSizeUnit mode)
  : TestCase ("URG Flag enabled packets check with ack filtering, and attribute setting" + std::to_string (mode))
{
  m_mode = mode;
}

void
AckFilterUrgFlagTest::DoRun (void)
{
  Ptr<CobaltQueueDisc> queue = CreateObject<CobaltQueueDisc> ();

  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;

  Address dest;

  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MinBytes", UintegerValue (pktSize)), true,
                         "Verify that we can actually set the attribute MinBytes");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue ("50ms")), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue ("4ms")), true,
                         "Verify that we can actually set the attribute Target");

  if (m_mode == QueueSizeUnit::BYTES)
    {
      modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
      modeSize = 1;
    }
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 1500))),
                         true, "Verify that we can actually set the attribute MaxSize");
  queue->Initialize ();

  TcpHeader tcpHdr1;
  uint8_t flags1 =TcpHeader::ACK|TcpHeader::URG;
  tcpHdr1.SetFlags (flags1);
  SequenceNumber32 num1 (1);
  tcpHdr1.SetAckNumber (num1);
  tcpHdr1.SetSourcePort(22);
  tcpHdr1.SetDestinationPort(25);


  TcpHeader tcpHdr2;
  uint8_t flags2 =TcpHeader::ACK;
  tcpHdr2.SetFlags (flags2);
  SequenceNumber32 num2 (1501);
  tcpHdr2.SetAckNumber (num2);
  tcpHdr2.SetSourcePort(22);
  tcpHdr2.SetDestinationPort(25);

  

  Ptr<Packet> p1, p2;
  p1 = Create<Packet> (pktSize);
  p1->AddHeader(tcpHdr1);
  p2 = Create<Packet> (pktSize);
  p2->AddHeader(tcpHdr2);


  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 0 * modeSize, "There should be no packets in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p1, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue");
  queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest,0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 2 * modeSize, "There should be two packet in queue, two packets means it wasnt dropped");
  }

  /**
   * This is Test Case 3 : Enqueued a TCP packet with only ACK Flag enabled and
   * some sequence number, then enqueue a TCP Packet with only ACK Flag enabled
   * and higher sequence number. The packet at HEAD of the queue will be dropped 
   * since the loss of this ACK will not result in any information loss at TCP 
   * Sender Side.
   */

class AckFilterDropHeadTest : public TestCase
{
public:
  /**
   * Constructor
   *
   * \param mode the mode
   */
  AckFilterDropHeadTest (QueueSizeUnit mode);
  void AddPacket(Ptr<Packet> p,Ptr<CobaltQueueDisc> queue, Ipv4Header hdr);
  virtual void DoRun (void);

  /**
   * Queue test size function
   * \param queue the queue disc
   * \param size the size
   * \param error the error string
   *
   */

private:
  QueueSizeUnit m_mode; ///< mode
};

AckFilterDropHeadTest::AckFilterDropHeadTest (QueueSizeUnit mode)
  : TestCase ("ACK flag enabled TCP Packets with ack filtering, and attribute setting" + std::to_string (mode))
{
  m_mode = mode;
}

void
AckFilterDropHeadTest::AddPacket (Ptr<Packet> p, Ptr<CobaltQueueDisc> queue, Ipv4Header hdr)
{
  // Ptr<Packet> p = Create<Packet> (100);
  Address dest;
  Ptr<Ipv4QueueDiscItem> item = Create<Ipv4QueueDiscItem> (p, dest, 0, hdr);
  queue->Enqueue (item);
}

void
AckFilterDropHeadTest::DoRun (void)
{
  Ptr<CobaltQueueDisc> queue = CreateObjectWithAttributes<CobaltQueueDisc> ("UseAckFilter", BooleanValue (true));

  uint32_t pktSize = 1000;
  uint32_t modeSize = 0;

  Address dest;

  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MinBytes", UintegerValue (pktSize)), true,
                         "Verify that we can actually set the attribute MinBytes");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Interval", StringValue ("50ms")), true,
                         "Verify that we can actually set the attribute Interval");
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("Target", StringValue ("4ms")), true,
                         "Verify that we can actually set the attribute Target");

  if (m_mode == QueueSizeUnit::BYTES)
    {
      modeSize = pktSize;
    }
  else if (m_mode == QueueSizeUnit::PACKETS)
    {
      modeSize = 1;
    }
  NS_TEST_EXPECT_MSG_EQ (queue->SetAttributeFailSafe ("MaxSize", QueueSizeValue (QueueSize (m_mode, modeSize * 1500))),
                         true, "Verify that we can actually set the attribute MaxSize");
  queue->Initialize ();

  TcpHeader tcpHdr1;
  tcpHdr1.SetFlags (TcpHeader::SYN);
  SequenceNumber32 num1 (1);
  tcpHdr1.SetAckNumber (num1);
  tcpHdr1.SetSourcePort(22);
  tcpHdr1.SetDestinationPort(25);

  TcpHeader tcpHdr2;
  tcpHdr2.SetFlags (TcpHeader::ACK);
  SequenceNumber32 num2 (1501);
  tcpHdr2.SetAckNumber (num2);
  tcpHdr2.SetSourcePort(22);
  tcpHdr2.SetDestinationPort(25);

  TcpHeader tcpHdr3;
  tcpHdr3.SetFlags (TcpHeader::ACK);
  SequenceNumber32 num3 (1502);
  tcpHdr3.SetAckNumber (num3);
  tcpHdr3.SetSourcePort(22);
  tcpHdr3.SetDestinationPort(25);

  TcpHeader tcpHdr4;
  tcpHdr4.SetFlags (TcpHeader::ACK);
  SequenceNumber32 num4 (1503);
  tcpHdr4.SetAckNumber (num4);
  tcpHdr4.SetSourcePort(22);
  tcpHdr4.SetDestinationPort(25);

  TcpHeader tcpHdr5;
  tcpHdr5.SetFlags (TcpHeader::FIN);
  SequenceNumber32 num5 (1504);
  tcpHdr5.SetAckNumber (num5);
  tcpHdr5.SetSourcePort(22);
  tcpHdr5.SetDestinationPort(25);


  Ptr<Packet> p1, p2, p3, p4, p5;
  p1 = Create<Packet> (pktSize);
  p1->AddHeader(tcpHdr1);
  p2 = Create<Packet> (pktSize);
  p2->AddHeader(tcpHdr2);
  p3 = Create<Packet> (pktSize);
  p3->AddHeader(tcpHdr3);
  p4 = Create<Packet> (pktSize);
  p4->AddHeader(tcpHdr4);
  p5 = Create<Packet> (pktSize);
  p5->AddHeader(tcpHdr5);

  Ipv4Header hdr;
  hdr.SetPayloadSize (100);
  hdr.SetSource (Ipv4Address ("10.10.1.1"));
  hdr.SetDestination (Ipv4Address ("10.10.1.2"));
  hdr.SetProtocol (6);

  Ipv4Header hdr1;
  hdr1.SetPayloadSize (100);
  hdr1.SetSource (Ipv4Address ("10.10.1.2"));
  hdr1.SetDestination (Ipv4Address ("10.10.1.3"));
  hdr1.SetProtocol (6);

  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 0 * modeSize, "There should be no packets in queue");
  // queue->Enqueue (Create<CobaltQueueDiscTestItem> (p1, dest,0, false));
  
  AddPacket (p1, queue, hdr);
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 1 * modeSize, "There should be one packet in queue");
  
  AddPacket (p2, queue, hdr);
  // queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest, 0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 2 * modeSize, "There should be two packet in queue");

  AddPacket (p3, queue, hdr1);
  // queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest, 0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 3 * modeSize, "There should be three packet in queue");

  AddPacket (p4, queue, hdr);
  // queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest, 0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 3 * modeSize, "There should be three packet in queue, 2nd packet dropped");

  AddPacket (p5, queue, hdr);
  // queue->Enqueue (Create<CobaltQueueDiscTestItem> (p2, dest, 0, false));
  NS_TEST_EXPECT_MSG_EQ (queue->GetCurrentSize ().GetValue (), 4 * modeSize, "There should be four packet in queue");

 }

static class CobaltQueueDiscTestSuite : public TestSuite
{
public:
  CobaltQueueDiscTestSuite ()
    : TestSuite ("cobalt-queue-disc", UNIT)
  {
    // Test 1: simple enqueue/dequeue with no drops
    AddTestCase (new CobaltQueueDiscBasicEnqueueDequeue (PACKETS), TestCase::QUICK);
    AddTestCase (new CobaltQueueDiscBasicEnqueueDequeue (BYTES), TestCase::QUICK);
    // // Test 2: Drop test
    AddTestCase (new CobaltQueueDiscDropTest (), TestCase::QUICK);
    // Test 3: Drop test
    AddTestCase (new CobaltBasicSynAckTest (PACKETS), TestCase::QUICK);
    // Test 4:
    AddTestCase (new AckFilterEceCwrFlagTest(PACKETS), TestCase::QUICK);
    // Test 5:
    AddTestCase (new AckFilterSackPermittedTest(PACKETS), TestCase::QUICK);

    AddTestCase (new AckFilterUdpEnqueueTest(PACKETS), TestCase::QUICK);
    AddTestCase (new AckFilterUrgFlagTest(PACKETS), TestCase::QUICK);
    AddTestCase (new AckFilterDropHeadTest(PACKETS), TestCase::QUICK);

  }
} g_cobaltQueueTestSuite; ///< the test suite