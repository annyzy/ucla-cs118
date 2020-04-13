/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
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

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

using namespace std;
//ethernet_hdr *e_h_add;

namespace simple_router
{
    void SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
    {
      std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

      const Interface *iface = findIfaceByName(inIface);
      if (iface == nullptr)
      {
        std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
        return;
      }

      cerr << "---Start printing routing table---" << endl;
      std::cerr << getRoutingTable() << std::endl;
      cerr << "---Finish printing routing table---" << endl;

      //First, get Etherent header of the packet

      if (packet.size() < sizeof(ethernet_hdr))
      {
        cerr << " Error: invalid length" << endl;
        return;
      }
///////////////////////////////////////////
      //ethernet_hdr *e_h_add;
      ethernet_hdr *e_h_add = (ethernet_hdr *)packet.data();

      //Second, get the MAC address of the packet
      string packet_add = macToString(packet);
      string interface_add = macToString(iface->addr);
      string broadcast_add1 = "FF:FF:FF:FF:FF:FF";
      string broadcast_add2 = "ff:ff:ff:ff:ff:ff";

      if ((packet_add != interface_add) && (packet_add != broadcast_add1) && (packet_add != broadcast_add2))
      {
        cerr << " Ignore: packet not destined to the router " << endl;
        return;
      }
////////////////////////////////////////////
      uint16_t ether_type = ethertype((const uint8_t *)packet.data());

      if (ether_type == ethertype_ip)
      {
          cerr << "Doing IPv4 now..." << endl;
        //IPv4_Packet(packet, iface);
          ip_hdr *ip_h_add = (ip_hdr *)(packet.data() + sizeof(ethernet_hdr));

          if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr))
          {
            cerr << "Ignore: invalid packet length" << endl;
            return;
          }
          
          uint16_t ip_checksum = ip_h_add->ip_sum;
          ip_h_add->ip_sum =0;


          //uint16_t ip_checksum = ntohs(cksum((const void *)ip_h_add, sizeof(ip_hdr)));
          if (ip_checksum != cksum(ip_h_add, sizeof(ip_hdr)))
          {
            cerr << "Ignore: invalid checksum in ip packet" << endl;
            return;
          }

          uint32_t ip_dest = ip_h_add->ip_dst;
          for (std::set<Interface>::const_iterator it = m_ifaces.begin(); it != m_ifaces.end(); it++)
          {

            if (ip_h_add->ip_dst == it->ip)
            {
            //TODO: if packet carries carries ICMP paylod
            //dispatch
            Buffer mac(e_h_add->ether_shost[0], e_h_add->ether_shost[ETHER_ADDR_LEN]);
            m_arp.insertArpEntry(mac, ip_h_add->ip_src);

            if (ip_h_add->ip_p == ip_protocol_icmp)
            {
              icmp_hdr *icmp_h_add = (icmp_hdr *)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));


              // uint16_t icmp_checksum = ntohs(cksum((const void *)ip_h_add, sizeof(ip_hdr)));

              // if (icmp_checksum != 0xffff)
              // {
              //     cerr << "Error: invalid checksum in icmp packet" << endl;
              //     return;
              // }

              if (icmp_h_add->icmp_type == 8)
              {
                  cerr << "Process icmp echo message now" << endl;

                  if (  memcpy(e_h_add->ether_dhost, e_h_add->ether_shost, ETHER_ADDR_LEN)   <0 )
                  { 
                    cerr << "cannnot copy memory address 2 to address 1" << endl;
                    return;
                  }

                  if (   memcpy(e_h_add->ether_shost, iface->addr.data(), ETHER_ADDR_LEN) < 0 )
                  {
                    cerr << "cannnot copy memory address 2 to address 1" << endl;
                    return;                    
                  }

                  ip_h_add->ip_dst = ip_h_add->ip_src;
                  ip_h_add->ip_src = it->ip;
                  ip_h_add->ip_sum = 0;
                  ip_h_add->ip_sum = cksum(ip_h_add, sizeof(ip_hdr));

                  icmp_h_add->icmp_type = 0;
                  icmp_h_add->icmp_sum = 0;
                  icmp_h_add->icmp_sum = cksum(icmp_h_add, sizeof(icmp_hdr));

                  cerr << " Start printing echo reply message..." << endl;
                  print_hdrs(packet);
                  cerr << " Finish printing echo reply message..." << endl;

                  sendPacket(packet, iface->name);
                  cerr << "Finish processing ICMP packets" << endl;
                  return;
                }
                return;
              }
              return;
            }
          }

         // Verify checksum
          // uint16_t actual_cksum = ip_h_add->ip_sum;
          // ip_h_add->ip_sum = 0;

          // uint16_t expected_cksum = cksum((void*) ip_h_add, sizeof(ip_hdr));
          // if (actual_cksum != expected_cksum) 
          // {
          //   cerr << "Packet has invalid checksum, ignoring" << endl;
          // }

          ip_h_add->ip_ttl--;
          if (ip_h_add->ip_ttl <= 0)
          {
            cerr << "Discarded: Packet time-to-live exceed" << endl;
            return;
          }

            //recompute the checksum
            uint16_t new_ck = cksum((void *)ip_h_add, sizeof(ip_hdr));
            ip_h_add->ip_sum = new_ck;

          cerr << "Looking up ip entry in routing table now" << ipToString(ip_dest) << endl;
          RoutingTableEntry routingtable_entry = m_routingTable.lookup(ip_dest);

          uint32_t nexthop_gw = routingtable_entry.gw;
          const Interface *nextIface = findIfaceByName(routingtable_entry.ifName);

          //When your router receives an IP packet to be forwarded to a next-hop IP address, it should check ARP cache if it contains the corresponding MAC address:
          cerr << "Looking up arp cache for Ip-Mac mapping for this ip now" << ipToString(nexthop_gw) << endl;
          shared_ptr<ArpEntry> arpcache_entry = m_arp.lookup(nexthop_gw);

          if (arpcache_entry == nullptr)
          {
            cerr << "Next-hop IP not in ARP Cache, queuing ARP request" << std::endl;
            auto arp_request = m_arp.queueRequest(nexthop_gw, packet, nextIface->name);
            return;
          }

          if (  memcpy(e_h_add->ether_dhost, arpcache_entry->mac.data(), ETHER_ADDR_LEN) < 0)
          {
            cerr << "cannnot copy memory address 2 to address 1" << endl;
            return;
          }
          if (  memcpy(e_h_add->ether_shost, nextIface->addr.data(), ETHER_ADDR_LEN) < 0)
          {
            cerr << "cannnot copy memory address 2 to address 1" << endl;
            return;
          }

          cerr << "Start sending IPv4 packet now" << endl;

          cerr << "Start printing all IPv4 packets..." << endl;
          print_hdrs(packet);
          cerr << "Finish printing all IPv4 packets..." << endl;

          sendPacket(packet, nextIface->name);
          cerr << "Finish processing IPv4 Packet" << endl;
          return;
      }
      if (ether_type == ethertype_arp)
      {
          cerr << "Doing ARP now..." << endl;
          //ARP_Packet(packet, iface);
          arp_hdr *arp_h_add = (arp_hdr *)(packet.data() + sizeof(ethernet_hdr));

          //if the packet is arp request
          if (ntohs(arp_h_add->arp_op) == arp_op_request)
          {
            cerr << "Processing ARP request now " << endl;

            Buffer respond_p(sizeof(ethernet_hdr) + sizeof(arp_hdr));
            ethernet_hdr *respond_eth_hdr = (ethernet_hdr *)respond_p.data();
            arp_hdr *respond_arp_hdr = (arp_hdr *)(respond_p.data() + sizeof(ethernet_hdr));

            if (arp_h_add->arp_tip != iface->ip)
            {
              cerr << "Ignore: dropped the packet if there is no corresponding IP address" << endl;
              return;
            }

            if ( memcpy(respond_eth_hdr->ether_dhost, e_h_add->ether_shost, ETHER_ADDR_LEN)< 0)
            {
              cerr << "cannnot copy memory address 2 to address 1" << endl;
              return;
            }
            if ( memcpy(respond_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN) < 0)
            {
              cerr << "cannnot copy memory address 2 to address 1" << endl;
              return;
            }
            respond_eth_hdr->ether_type = htons(ethertype_arp);

            //Generate ARP header
            respond_arp_hdr->arp_hrd = htons(arp_hrd_ethernet); //0x0001
            respond_arp_hdr->arp_pro = htons(ethertype_ip);     //0x0800
            respond_arp_hdr->arp_hln = ETHER_ADDR_LEN;          //0x06
            respond_arp_hdr->arp_pln = 4;                       //0x04
            //Change to reply type
            respond_arp_hdr->arp_op = htons(arp_op_reply);

            if (memcpy(respond_arp_hdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN) <0)
            {
              cerr << "cannnot copy memory address 2 to address 1" << endl;
              return;
            }
            respond_arp_hdr->arp_sip = iface->ip;
            if (memcpy(respond_arp_hdr->arp_tha, arp_h_add->arp_sha, ETHER_ADDR_LEN) <0)
            {
              cerr << "cannnot copy memory address 2 to address 1" << endl;
              return;
            }
                        //Generate ARP reply packet
            
            respond_arp_hdr->arp_tip = arp_h_add->arp_sip;
            //Send ARP reply packet
            sendPacket(respond_p, iface->name);

            cerr << "Start printing ARP Reply Packet..." << endl;
            print_hdrs(respond_p);
            cerr << "Finish printing ARP Reply Packet..." << endl;

            cerr << "Finish processing ARP Request Packet" << endl;
          }
          //if the packet is arp reply
          else if (ntohs(arp_h_add->arp_op) == arp_op_reply)
          {
            cerr << "Processing ARP Reply Packet now..." << endl;

            Buffer arp_source_mac(ETHER_ADDR_LEN);

            //When router receives an ARP reply, it should record IP-MAC mapping information in ARP cache
            if (memcpy(arp_source_mac.data(), arp_h_add->arp_sha, ETHER_ADDR_LEN)<0)
            {
              cerr << "cannnot copy memory address 2 to address 1" << endl;
              return;
            }

            auto arp_request = m_arp.insertArpEntry(arp_source_mac, arp_h_add->arp_sip);

            if (arp_request == nullptr)
            {
              cerr << "Error: Arp entery cannot be inserted" << endl;
              return;
            }

            // Send out corresponding enqueued packets for this arp entry
            for (list<PendingPacket>::const_iterator i = arp_request->packets.begin(); i != arp_request->packets.end(); i++)
            {
              Buffer temp(i->packet);
              ethernet_hdr *temp_eth_hdr = (ethernet_hdr *)temp.data();

              string interface2(i->iface);
              if (  memcpy(temp_eth_hdr->ether_dhost, arp_h_add->arp_sha, ETHER_ADDR_LEN) <0 )
              {
                cerr << "cannnot copy memory address 2 to address 1" << endl;
                return;
              }
              if (memcpy(temp_eth_hdr->ether_shost, arp_h_add->arp_tha, ETHER_ADDR_LEN) <0)
              {
                cerr << "cannnot copy memory address 2 to address 1" << endl;
                return;
              }

              //Send out all corresponding enqueued packets
              //m_arp.removeRequest(arp_request); 
              sendPacket(temp, interface2);

              cerr << "Start printing all corresponding sent out enqueued packets..." << endl;
              print_hdrs(temp);
              cerr << "Finish printing all corresponding sent out enqueued packets..." << endl;

              cerr << "Finish processing ARP Reply Packet" << endl;
            }

            m_arp.removeRequest(arp_request);
          }
          else
          {
            cerr << "Ignore: other type arp" << endl;
          }
      }
      else
      {
        cerr << " Ignore: packet other than ARP and IPv4 " << endl;
        return;
      }     
    }


    // You should not need to touch the rest of this code.
    SimpleRouter::SimpleRouter()
        : m_arp(*this)
    {
    }

    void SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
    {
      m_pox->begin_sendPacket(packet, outIface);
    }

    bool SimpleRouter::loadRoutingTable(const std::string &rtConfig)
    {
      return m_routingTable.load(rtConfig);
    }

    void SimpleRouter::loadIfconfig(const std::string &ifconfig)
    {
      std::ifstream iff(ifconfig.c_str());
      std::string line;
      while (std::getline(iff, line))
      {
        std::istringstream ifLine(line);
        std::string iface, ip;
        ifLine >> iface >> ip;

        in_addr ip_addr;
        if (inet_aton(ip.c_str(), &ip_addr) == 0)
        {
          throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
        }

        m_ifNameToIpMap[iface] = ip_addr.s_addr;
      }
    }

    void SimpleRouter::printIfaces(std::ostream & os)
    {
      if (m_ifaces.empty())
      {
        os << " Interface list empty " << std::endl;
        return;
      }

      for (const auto &iface : m_ifaces)
      {
        os << iface << "\n";
      }
      os.flush();
    }

    const Interface *
    SimpleRouter::findIfaceByIp(uint32_t ip) const
    {
      auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface) {
        return iface.ip == ip;
      });

      if (iface == m_ifaces.end())
      {
        return nullptr;
      }

      return &*iface;
    }

    const Interface *
    SimpleRouter::findIfaceByMac(const Buffer &mac) const
    {
      auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface) {
        return iface.addr == mac;
      });

      if (iface == m_ifaces.end())
      {
        return nullptr;
      }

      return &*iface;
    }

    void SimpleRouter::reset(const pox::Ifaces &ports)
    {
      std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

      m_arp.clear();
      m_ifaces.clear();

      for (const auto &iface : ports)
      {
        auto ip = m_ifNameToIpMap.find(iface.name);
        if (ip == m_ifNameToIpMap.end())
        {
          std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
          continue;
        }

        m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
      }

      printIfaces(std::cerr);
    }

    const Interface *
    SimpleRouter::findIfaceByName(const std::string &name) const
    {
      auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface) {
        return iface.name == name;
      });

      if (iface == m_ifaces.end())
      {
        return nullptr;
      }

      return &*iface;
    }

} // namespace simple_router
