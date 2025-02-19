// Copyright Microsoft and Project Verona Contributors.
// SPDX-License-Identifier: MIT
#pragma once

#include "trieste.h"

#include <random>
#include <stdexcept>

namespace trieste
{
  class Fuzzer
  {
  private:
    std::vector<Pass> passes_;
    const wf::Wellformed* input_wf_;
    GenNodeLocationF generators_;
    size_t max_depth_;
    uint32_t start_seed_;
    uint32_t seed_count_;
    bool failfast_;
    bool check_props_;
    size_t start_index_;
    size_t end_index_;

  public:
    Fuzzer() {}

    Fuzzer(
      const std::vector<Pass>& passes,
      const wf::Wellformed& input_wf,
      GenNodeLocationF generators)
    : passes_(passes),
      input_wf_(&input_wf),
      generators_(generators),
      max_depth_(10),
      start_seed_(std::random_device()()),
      seed_count_(100),
      failfast_(false),
      check_props_(false),
      start_index_(1),
      end_index_(passes.size() - 1)
    {}

    Fuzzer(const Reader& reader)
    : Fuzzer(
        reader.passes(), reader.parser().wf(), reader.parser().generators())
    {}

    Fuzzer(const Writer& writer, GenNodeLocationF generators)
    : Fuzzer(writer.passes(), writer.input_wf(), generators)
    {}

    Fuzzer(const Rewriter& rewriter, GenNodeLocationF generators)
    : Fuzzer(rewriter.passes(), rewriter.input_wf(), generators)
    {}

    size_t max_depth() const
    {
      return max_depth_;
    }

    Fuzzer& max_depth(size_t max_depth)
    {
      max_depth_ = max_depth;
      return *this;
    }

    uint32_t start_seed() const
    {
      return start_seed_;
    }

    Fuzzer& start_seed(uint32_t seed)
    {
      start_seed_ = seed;
      return *this;
    }

    uint32_t seed_count() const
    {
      return seed_count_;
    }

    Fuzzer& seed_count(uint32_t seed_count)
    {
      seed_count_ = seed_count;
      return *this;
    }

    bool failfast() const
    {
      return failfast_;
    }

    Fuzzer& failfast(bool failfast)
    {
      failfast_ = failfast;
      return *this;
    }

    bool check_props() const
    {
      return check_props_;
    }

     Fuzzer& check_props(bool check)
    {
      check_props_ = check;
      return *this;
    }

    size_t start_index() const
    {
      return start_index_;
    }

    Fuzzer& start_index(size_t start_index)
    {
      if (start_index == 0)
      {
        throw std::invalid_argument("start_index must be greater than 0");
      }

      start_index_ = start_index;
      return *this;
    }

    size_t end_index() const
    {
      return end_index_;
    }

    Fuzzer& end_index(size_t end_index)
    {
      end_index_ = end_index;
      return *this;
    }

    int test()
    {
      WFContext context;
      int ret = 0;
      for (size_t i = start_index_; i <= end_index_; i++)
      {
        auto& pass = passes_.at(i - 1);
        auto& wf = pass->wf();
        auto& prev = i > 1 ? passes_.at(i - 2)->wf() : *input_wf_;

        std::cout << "Pass: " << pass->name() << std::endl; 
        if (!prev || !wf)
        {
          logging::Info() << "Skipping pass: " << pass->name() << std::endl;
          continue;
        }

        logging::Info() << "Testing pass: " << pass->name() << std::endl;
        context.push_back(prev);
        context.push_back(wf);

        auto properties = pass->props();
        // Check properties starting from other roots than Top 
        if (check_props_ && !properties.empty()){
          for (auto [root, props] : properties){
            ret = run_test(start_seed_, seed_count_, prev, wf, pass, root, props); 
          } 
        // If not checked WF for a full tree (rooted with Top) when checking
        // properties, check WF 
        } if (properties.find(Top) == properties.end()){
          //Check WF only 
          ret = run_test(start_seed_, seed_count_, prev, wf, pass, Top, {}); 
        }
        context.pop_front();
        context.pop_front();
      }

      return ret;
    }

  int run_test(size_t start_seed, 
               size_t seed_count,
               wf::Wellformed prev,
               wf::Wellformed wf,
               Pass pass, 
               Token root, 
               std::vector<Prop> props){
    int ret; 
    for (size_t seed = start_seed; seed < start_seed + seed_count;
             seed++)
        {
          // Gen tree 
          auto ast = prev.gen(root, generators_, seed, max_depth_);
          logging::Trace() << "============" << std::endl
                           << "Pass: " << pass->name() << ", seed: " << seed
                           << std::endl
                           << "------------" << std::endl
                           << ast << "------------" << std::endl;

          auto ast_copy = ast->clone();
          auto [new_ast, count, changes] = pass->run(ast);
          logging::Trace() << new_ast << "------------" << std::endl
                           << std::endl;

          auto ok = wf.build_st(new_ast);
          Nodes errors;
          if (ok)
          {
            new_ast->get_errors(errors);
            if (!errors.empty())
              // Pass added error nodes, so doesn't need to satisfy wf.
              continue;
          }
          ok = wf.check(new_ast) && ok;

          if (!ok)
          {
            logging::Error err;
            if (!logging::Trace::active())
            {
              err << "============" << std::endl
                  << "Pass: " << pass->name() << ", seed: " << seed << std::endl
                  << "------------" << std::endl
                  << ast_copy << "------------"
                  << std::endl
                  << new_ast;
            }

            err << "============" << std::endl
                << "Failed pass: " << pass->name() << ", seed: " << seed
                << std::endl;
            ret = 1;
            if (failfast_)
              return ret;
          }
          // Only test properties if pass produced well-formed tree 
          // and there are props to test 
          // TODO: report if properties are tester, 
          // now properties are silently not run when we detect an error 
          else if(check_props_)
          {
            for(auto prop : props){
              auto result = prop.f(ast, new_ast); 
              if (!result) 
              {
                Node err_ast = result.reason(); 
                auto err_msg = "property '" + prop.name + "' failed\n";
                errors.push_back(Error << (ErrorMsg ^ err_msg) << err_ast);
                ok = false;
              }
            }
            if (!ok)
            {
              logging::Error err;
              err << "============" << std::endl
                  << "Pass: " << pass->name() << ", seed: " << seed << std::endl
                  << "------------" << std::endl
                  << ast_copy << "------------"
                  << std::endl
                  << new_ast;

            size_t err_count = 0;
            for (auto& error : errors)
            {
              err << "------------" << std::endl;
              for (auto& child : *error)
              {
                if (child->type() == ErrorMsg)
                  err << child->location().view() << std::endl;
                else
                {
                  err << "-- " << child->location().origin_linecol() << std::endl
                      << child->location().str() << std::endl; 
                }
              }
              if (err_count++ > 20)
              {
                err << "Too many errors, stopping here" << std::endl;
                break;
              }
            }

            err << "============" << std::endl
                << "Failed pass: " << pass->name() << ", seed: " << seed
                << std::endl;

            ret = 1;
            if (failfast_)
              return ret;
            }
          }
        }
        return ret; 
    } 
  };
}
