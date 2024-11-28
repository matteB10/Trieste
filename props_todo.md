What should the property function look like? 

A property should have:

* Pre and post trees? ok 

Other things to add:
* Flags for enabling/disabling pbt ok
* Report errors 
    1. By name of property / specified error message  ok 
    2. Point to specific error? 

library functions for collecting nodes:

* auto group = n->get_first(Group); ?
* auto groups = n->get_all(Group); ?
      
Unit tests?
```exprs.unit_test(
      parse ("1 + 2") == Add (Int 1) (Int 2);
      Group ((Int 1) Add (Int 2)) == Add (Int 1) (Int 2);
    ); ```