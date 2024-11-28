#pragma once 

#include "token.h"

namespace trieste 
{
    namespace prop 
    {
      struct PropResult {
          std::optional<Node> reason_;

          operator bool() {
              return !reason_;
          }

          Node reason() {
              if(reason_) return *reason_;
              return nullptr;
          }
      };

      inline PropResult Success() { return {std::nullopt};}
      inline PropResult Fail() { return {nullptr}; }
      inline PropResult Fail(Node reason) { return {reason}; }
    }
}