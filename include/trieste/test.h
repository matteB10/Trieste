#pragma once 

#include "token.h"
#include "ast.h"
#include "rewrite.h"

namespace trieste {

    namespace unit_test{  

    using assertFunction = std::function<bool(Node,Node)>;
    using namespace detail;
    struct Assertion {
        
        Node before_;
        std::optional<Node> expected_; 
        std::string assert_fun; 
        

        assertFunction assertion; 

        Node before() {
            return before_; 
        }
        Node expected() {
            return expected_ ? expected_.value() : nullptr; 
        }
        std::string type() 
        {
            return assert_fun;
        }
    };

    struct Test {
        std::string desc_; 
        std::vector<Assertion> assertions;
        

        Test(std::string desc):desc_(desc){

        } 

        void rewritesInto(Node before, Node expected){
            if (before->type() != Top) before = TestTop << before; 
            
            assertions.push_back(
                {before, 
                expected,
                 "rewrites into",
                 [](Node res, Node exp)
                    {
                    return res->equals(exp);
                    }
                }
            );
        }

        void rewritesIntoErr(Node before){
            if (before->type() != Top) before = TestTop << before;
            
            assertions.push_back(
                {before, 
                std::nullopt,
                "expected error",
                 [](Node res, Node )
                    {
                    // Add dummy root since res might itself be the Error node
                    return (TestTop << res)->get_contains_error();
                    }
                }
            );
        }
    };

    }
    
}