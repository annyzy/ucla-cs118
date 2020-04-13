/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

using namespace std;

namespace simple_router
{

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
// bool checkvalid(shared_ptr<ArpEntry> arpEPtr)
// {
//   return !arpEPtr->isValid;
// }


void ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  auto now = steady_clock::now();

  //list<shared_ptr<ArpRequest>>iterator i;
  for (list<shared_ptr<ArpRequest>>::iterator i = m_arpRequests.begin(); i != m_arpRequests.end();)
  {
    if ((*i)->nTimesSent >= MAX_SENT_TIME)
    {
      i = m_arpRequests.erase(i);
      
    }
      // Send arp request
      // Create a request packet
      //uint8_t req_len = sizeof(ethernet_hdr) + sizeof(arp_hdr);
      else
      {
      Buffer packetBuffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
      //uint8_t *req_pack = (uint8_t *)packetBuffer.data();
      ethernet_hdr *eth_h_dr = (ethernet_hdr *)packetBuffer.data();
      arp_hdr *arp_h_dr = (arp_hdr *)(packetBuffer.data() + sizeof(ethernet_hdr));
      /* Ethernet header*/

      //string iface_name = (*i)->packets.front().iface;
      const Interface *iface = m_router.findIfaceByName((*i)->packets.front().iface);
      memcpy(eth_h_dr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(eth_h_dr->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
      eth_h_dr->ether_type = htons(ethertype_arp);

      /* ARP header*/
      arp_h_dr->arp_hrd = htons(arp_hrd_ethernet);
      arp_h_dr->arp_pro = htons(ethertype_ip);
      arp_h_dr->arp_hln = ETHER_ADDR_LEN;
      arp_h_dr->arp_pln = 4;
      arp_h_dr->arp_op = htons(arp_op_request);
      memcpy(arp_h_dr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      arp_h_dr->arp_sip = iface->ip;
      memcpy(arp_h_dr->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
      arp_h_dr->arp_tip = (*i)->ip;

      //Send request packet
      cerr << " Send arp request " << iface->name << "at time" << (*i)->nTimesSent + 1 << endl;
      cerr << "Start printing arp request packet..." << endl;
      print_hdrs(packetBuffer);
      cerr << "Finish printing arp request packet..." << endl;
      m_router.sendPacket(packetBuffer, iface->name);

      //increment time
      (*i)->timeSent = now;
      (*i)->nTimesSent++;
      }
      //next arp request
      i++;
    }

  list<shared_ptr<ArpEntry>>::iterator i;
  for (list<shared_ptr<ArpEntry>>::iterator i = m_cacheEntries.begin(); i != m_cacheEntries.end();)
  {
    if (!(*i)->isValid)
    {
      i = m_cacheEntries.erase(i);
      continue;
    }
    i++;
  }
  // m_cacheEntries.remove_if(checkvalid);
  // i++;
  // }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter &router)
    : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto &entry : m_cacheEntries)
  {
    if (entry->isValid && entry->ip == ip)
    {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer &packet, const std::string &iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                              [ip](const std::shared_ptr<ArpRequest> &request) {
                                return (request->ip == ip);
                              });

  if (request == m_arpRequests.end())
  {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void ArpCache::removeRequest(const std::shared_ptr<ArpRequest> &entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                              [ip](const std::shared_ptr<ArpRequest> &request) {
                                return (request->ip == ip);
                              });
  if (request != m_arpRequests.end())
  {
    return *request;
  }
  else
  {
    return nullptr;
  }
}

void ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void ArpCache::ticker()
{
  while (!m_shouldStop)
  {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto &entry : m_cacheEntries)
      {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO))
        {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream &
operator<<(std::ostream &os, const ArpCache &cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto &entry : cache.m_cacheEntries)
  {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
