## Run the code
```sh
python3 firewall.py
```

## Test

## Complexities
A rule based tree is built when constructing an instance of `Firewall`. The rules are imported from a csv file called `rules.csv`. This tree makes checking each packet super efficient: `O(1)`. However the construction of the tree in the beginning takes a long time because of the size of rules. The tree also costs a lot of space, say there are 500k ringle IP/port rules, the total memory the tree takes is: `500K * 4 * 255^4 * 65536`