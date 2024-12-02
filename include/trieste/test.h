#pragma once 

#include "token.h"
#include "ast.h"

namespace trieste {

    namespace unit_test{  

    
    inline bool type_equals (Node n, Node m){
        return n->type() == m->type();
    }

    inline bool value_equals (Node n, Node m){
        return n->location().view() == m->location().view();
    }
    
    inline bool node_equals (Node n, Node m)
    { 
        NodeIt n_it, m_it; 
        if (type_equals(n,m) && value_equals(n,m)){
            n_it = n->begin();
            m_it = m->begin(); 
            while (!(n_it == n->end()) || !(m_it == m->end())){
                if(!node_equals(*n_it,*m_it)) return false; 
                n_it++; m_it++; 
            }
        }
        return true; 
    }

    struct Assertion {
        Node before_;
        Node expected_;
        std::function<bool(Node,Node)> assertion; 
    };

    struct Test {
        std::string desc_; 
        std::vector<Assertion> assertions;
        

        Test(std::string desc):desc_(desc){

        } 

        void isEqual(Node before, Node expected){
            assertions.push_back(
                {before, 
                 expected, 
                 [](Node res, Node exp)
                    {
                    return node_equals(res,exp);
                    }
                }
            );
        }
    };

    }
    
}