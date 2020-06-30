#include "ns3/object-factory.h"
#include <list>
#include <map>
#include "ns3/pointer.h"
#include "ns3/queue-disc.h"
#include "queue-disc.h"

namespace ns3 {

class Ipv4QueueDiscItem;
template <typename Item>
class Queue;

class AckFilter : public Object
{
public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

public:
  /**
   * \brief Get the type ID.
   * \return the object TypeId
   */
//  static TypeId GetTypeId (void);
/**
 * \brief AckFilter constructor
 */
  AckFilter ();

  virtual ~AckFilter ();
  virtual bool AckFilterMain (Ptr<Queue<QueueDiscItem>> queue, Ptr<QueueDiscItem> item) const;
  virtual bool AckFilterMayDrop (Ptr<QueueDiscItem> item, uint32_t tstamp,uint32_t tsecr) const;
  virtual int AckFilterSackCompare (Ptr<QueueDiscItem> item_a, Ptr<QueueDiscItem> item_b) const;
};

}
