# This version of firewall is the most time efficient
# The constructor builds a Port bitmap with whitelist ports slots marked as True
# The constructor builds a IP tree with whitelist IP nodes marked as True

import unittest
import csv

class Firewall:
  def __init__(self, filePath):
    self.root = { 'inbound': {}, 'outbound': {} }
    self.root['inbound']['tcp'] = {'ips': {} }
    self.root['inbound']['udp'] = {'ips': {} }
    self.root['outbound']['tcp'] = {'ips': {} }
    self.root['outbound']['udp'] = {'ips': {} }
    self.test = 'It works'
    self.rules = []
    file = "./rules.csv"
    line_count = 0
    with open(file) as csvFile:
        readCSV = csv.reader(csvFile, delimiter=',')
        for row in readCSV:
            if line_count == 0:
                # print(f'Column names are {", ".join(row)}')
                line_count += 1
            else:
                # print(f'\tdirection: {row[0]}, type: {row[1]}, port: {row[2]}, IP: {row[3]}')
                self.rules.append(row)
                line_count += 1
    # print(f'Processed {line_count} lines.')
    print('Rules:')
    for rule in self.rules:
      print(rule)
      dir = rule[0]
      type = rule[1]
      ports = rule[2]
      ips = rule[3]

      ## Mark valid ips
      if '-' in ips:
        ipRange = ips.split('-')
        startIP = ipRange[0]
        endIP = ipRange[1]
        startSegments = startIP.split('.')
        endSegments = endIP.split('.')
        for i in range(4):
          startSegments[i] = int(startSegments[i])
          endSegments[i] = int(endSegments[i])
        # print('IP range:', startPort, 'to', endPort)
        for i_0 in range(0, 256):
          lowerBound = startSegments[0]
          upperBound = endSegments[0]
          curr = i_0
          if curr < lowerBound or curr > upperBound:
            continue
          for i_1 in range(0, 256):
            lowerBound = startSegments[0]*1000 + startSegments[1]
            upperBound = endSegments[0]*1000 + endSegments[1]
            curr = i_0*1000 + i_1
            if curr < lowerBound or curr > upperBound:
              continue
            for i_2 in range(0, 256):
              lowerBound = startSegments[0]*1000*1000 + startSegments[1]*1000 + startSegments[2]
              upperBound = endSegments[0]*1000*1000 + endSegments[1]*1000 + endSegments[2]
              curr = i_0*1000000 + i_1*1000 + i_2
              if curr < lowerBound or curr > upperBound:
                continue
              for i_3 in range(0, 256):
                lowerBound = startSegments[0]*1000*1000*1000 + startSegments[1]*1000*1000 + startSegments[2]*1000 + startSegments[3]
                upperBound = endSegments[0]*1000*1000*1000 + endSegments[1]*1000*1000 + endSegments[2]*1000 + endSegments[3]
                curr = i_0*1000*1000*1000 + i_1*1000*1000 + i_2*1000 + i_3
                if curr < lowerBound or curr > upperBound:
                  continue
                if i_0 not in self.root[dir][type]['ips']:
                  self.root[dir][type]['ips'][i_0] = {}
                if i_1 not in self.root[dir][type]['ips'][i_0]:
                  self.root[dir][type]['ips'][i_0][i_1] = {}
                if i_2 not in self.root[dir][type]['ips'][i_0][i_1]:
                  self.root[dir][type]['ips'][i_0][i_1][i_2] = {}
                if i_3 not in self.root[dir][type]['ips'][i_0][i_1][i_2]:
                  self.root[dir][type]['ips'][i_0][i_1][i_2][i_3] = [False for i in range(65535)]
                ## Mark valid port numbers
                if '-' in ports:
                  portRange = ports.split('-')
                  startPort = int(portRange[0])
                  endPort = int(portRange[1])
                  # print('Port range:', startPort, 'to', endPort)
                  for i in range(startPort-1, endPort):
                    self.root[dir][type]['ips'][i_0][i_1][i_2][i_3][i] = True
                else:
                  port = int(ports)
                  # print('Single port number:', port)
                  self.root[dir][type]['ips'][i_0][i_1][i_2][i_3][port-1] = True
                # print(self.root[dir][type]['ports'])


      else:
        singleIP = ips
        segments = singleIP.split('.')
        for i in range(len(segments)):
          segments[i] = int(segments[i])
        # print('Single IP number:', singleIP)
        if segments[0] not in self.root[dir][type]['ips']:
          self.root[dir][type]['ips'][segments[0]] = {}
        if segments[1] not in self.root[dir][type]['ips'][segments[0]]:
          self.root[dir][type]['ips'][segments[0]][segments[1]] = {}
        if segments[2] not in self.root[dir][type]['ips'][segments[0]][segments[1]]:
          self.root[dir][type]['ips'][segments[0]][segments[1]][segments[2]] = {}
        if segments[3] not in self.root[dir][type]['ips'][segments[0]][segments[1]][segments[2]]:
          self.root[dir][type]['ips'][segments[0]][segments[1]][segments[2]][segments[3]] = [False for i in range(65535)]
        ## Mark valid port numbers
        if '-' in ports:
          portRange = ports.split('-')
          startPort = int(portRange[0])
          endPort = int(portRange[1])
          # print('Port range:', startPort, 'to', endPort)
          for i in range(startPort-1, endPort):
            self.root[dir][type]['ips'][segments[0]][segments[1]][segments[2]][segments[3]][i] = True
        else:
          port = int(ports)
          # print('Single port number:', port)
          self.root[dir][type]['ips'][segments[0]][segments[1]][segments[2]][segments[3]][port-1] = True
        # print(self.root[dir][type]['ports'])

  def accept_packet(self, dir, type, port, ip):
    ips = ip.split('.')
    segment_0 = int(ips[0])
    segment_1 = int(ips[1])
    segment_2 = int(ips[2])
    segment_3 = int(ips[3])

    # if the packet exists in the tree node
    if segment_0 in self.root[dir][type]['ips'] and \
      segment_1 in self.root[dir][type]['ips'][segment_0] and \
      segment_2 in self.root[dir][type]['ips'][segment_0][segment_1] and \
      segment_3 in self.root[dir][type]['ips'][segment_0][segment_1][segment_2] and \
      self.root[dir][type]['ips'][segment_0][segment_1][segment_2][segment_3][port-1]:
      return True
    # otherwise return False
    return False

class Test(unittest.TestCase):
    def test_fw(self):
        file = "./rules.csv"
        fw = Firewall(file)

        ## Matches 1st rule
        packet = ("inbound", "tcp", 80, "192.168.1.2")
        expected = True
        self.assertEqual(expected, fw.accept_packet(packet[0],packet[1],packet[2],packet[3]), "Test case #1: should accept this packet")

        ## Matches 2nd rule
        packet = ("outbound", "tcp", 10234, "192.168.10.11")
        expected = True
        self.assertEqual(expected, fw.accept_packet(packet[0],packet[1],packet[2],packet[3]), "Test case #2: should accept this packet")

        ## Matches 3rd rule
        packet = ("inbound", "udp", 53, "192.168.2.1")
        expected = True
        self.assertEqual(expected, fw.accept_packet(packet[0],packet[1],packet[2],packet[3]), "Test case #3: should accept this packet")

        ## Matches 4th rule
        packet = ("outbound", "udp", 1500, "52.12.48.92")
        expected = True
        self.assertEqual(expected, fw.accept_packet(packet[0],packet[1],packet[2],packet[3]), "Test case #4: should accept this packet")

        packet = ("inbound", "tcp", 81, "192.168.1.2")
        expected = False
        self.assertEqual(expected, fw.accept_packet(packet[0],packet[1],packet[2],packet[3]), "Test case #5: should reject this packet")

        packet = ("inbound", "udp", 24, "52.12.48.92")
        expected = False
        self.assertEqual(expected, fw.accept_packet(packet[0],packet[1],packet[2],packet[3]), "Test case #6: should reject this packet")

        packet = ("outbound", "udp", 158, "142.12.48.92")
        expected = False
        self.assertEqual(expected, fw.accept_packet(packet[0],packet[1],packet[2],packet[3]), "Test case #7: should reject this packet")

        packet = ("inbound", "udp", 50, "192.170.16.100")
        expected = False
        self.assertEqual(expected, fw.accept_packet(packet[0],packet[1],packet[2],packet[3]), "Test case #8: should reject this packet")

if __name__ == '__main__':
    test = Test()
    test.test_fw()