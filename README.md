## Run the code
```sh
python3 firewall.py
```

## Test
```
packet = ("inbound", "tcp", 80, "192.168.1.2") => True
packet = ("outbound", "tcp", 10234, "192.168.10.11") => True
packet = ("inbound", "udp", 53, "192.168.2.1") => True
packet = ("outbound", "udp", 1500, "52.12.48.92") => True
packet = ("inbound", "tcp", 81, "192.168.1.2") => False
packet = ("inbound", "udp", 24, "52.12.48.92") => False
packet = ("outbound", "udp", 158, "142.12.48.92") => False
packet = ("inbound", "udp", 50, "192.170.16.100") => False
```

## Complexities
A rule based tree is built when constructing an instance of `Firewall`. The rules are imported from a csv file called `rules.csv`. This tree makes checking each packet super efficient: `O(1)`. However the construction of the tree in the beginning takes a long time because of the size of rules. The tree also costs a lot of space, say there are 500k single items, the total memory the tree takes is: `500K * ( 1("inbound": 0; "outbound": 1) + 1("TCP": 0; "UDP": 1) + 1*4 + 1) bytes = 3.5 kilobytes`