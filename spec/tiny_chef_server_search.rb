#
# Author:: John Keiser (<jkeiser@opscode.com>)
# Copyright:: Copyright (c) 2012 Opscode, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'chef/mixin/deep_merge'

class TinyChefServer
  # /search
  class SearchesEndpoint < RestBase
    def get(request)
      # Get the result
      result_hash = {}
      indices = (%w(client environment node role) + data['data'].keys).sort
      indices.each do |index|
        result_hash[index] = build_uri(request.base_uri, request.rest_path + [index])
      end
      json_response(200, result_hash)
    end
  end

  # /search/INDEX
  class SearchEndpoint < RestBase
    def get(request)
      results = search(request)
      results['rows'] = results['rows'].map { |name,uri,value,search_value| value }
      json_response(200, results)
    end

    def post(request)
      full_results = search(request)
      keys = JSON.parse(request.body, :create_additions => false)
      partial_results = full_results['rows'].map do |name, uri, doc, search_value|
        data = {}
        keys.each_pair do |key, path|
          if path.size > 0
            value = search_value
            path.each do |path_part|
              value = value[path_part] if !value.nil?
            end
            data[key] = value
          else
            data[key] = nil
          end
        end
        {
          'url' => uri,
          'data' => data
        }
      end
      json_response(200, {
        'rows' => partial_results,
        'start' => full_results['start'],
        'total' => full_results['total']
      })
    end

    private

    def search_container(request, index)
      case index
      when 'client'
        [ data['clients'], Proc.new { |client, name| DataExpander.expand_client(client, name) }, build_uri(request.base_uri, [ 'clients' ]) ]
      when 'node'
        [ data['nodes'], Proc.new { |node, name| DataExpander.expand_node(node, name) }, build_uri(request.base_uri, [ 'nodes' ]) ]
      when 'environment'
        [ data['environments'], Proc.new { |environment, name| DataExpander.expand_environment(environment, name) }, build_uri(request.base_uri, [ 'environments' ]) ]
      when 'role'
        [ data['roles'], Proc.new { |role, name| DataExpander.expand_role(role, name) }, build_uri(request.base_uri, [ 'roles' ]) ]
      else
        [ data['data'][index], Proc.new { |data_bag_item, id| DataExpander.expand_data_bag_item(data_bag_item, index, id, 'DELETE') }, build_uri(request.base_uri, [ 'data', index ]) ]
      end
    end

    def expand_for_indexing(value, index, id)
      if index == 'node'
        result = {}
        Chef::Mixin::DeepMerge.deep_merge!(value['default'] || {}, result)
        Chef::Mixin::DeepMerge.deep_merge!(value['normal'] || {}, result)
        Chef::Mixin::DeepMerge.deep_merge!(value['override'] || {}, result)
        Chef::Mixin::DeepMerge.deep_merge!(value['automatic'] || {}, result)
        result['recipe'] = []
        result['role'] = []
        if value['run_list']
          value['run_list'].each do |run_list_entry|
            if run_list_entry =~ /^(recipe|role)\[(.*)\]/
              result[$1] << $2
            end
          end
        end
        value.each_pair do |key, value|
          result[key] = value unless %w(default normal override automatic).include?(key)
        end
        result

      elsif !%w(client environment role).include?(index)
        DataExpander.expand_data_bag_item(value, index, id, 'GET')
      else
        value
      end
    end

    def search(request)
      # Extract parameters
      index = request.rest_path[1]
      query_string = request.query_params['q'] || '*:*'
      solr_query = SolrParser.new(query_string).parse
      sort_string = request.query_params['sort']
      start = request.query_params['start']
      start = start.to_i if start
      rows = request.query_params['rows']
      rows = rows.to_i if rows

      # Get the search container
      container, expander, base_uri = search_container(request, index)
      if container.nil?
        raise RestErrorResponse.new(404, "Object not found: #{build_uri(request.base_uri, request.rest_path)}")
      end

      # Search!
      result = []
      container.each_pair do |name,value|
        expanded = expander.call(JSON.parse(value, :create_additions => false), name)
        result << [ name, build_uri(base_uri, [name]), expanded, expand_for_indexing(expanded, index, name) ]
      end
      result = result.select do |name, uri, value, search_value|
        solr_query.matches_doc?(SolrDoc.new(search_value, name))
      end
      total = result.size

      # Sort
      if sort_string
        sort_key, sort_order = sort_string.split(/\s+/, 2)
        result = result.sort_by { |name,uri,value,search_value| SolrDoc.new(search_value, name)[sort_key] }
        result = result.reverse if sort_order == "DESC"
      end

      # Paginate
      if start
        result = result[start..start+(rows||-1)]
      end
      {
        'rows' => result,
        'start' => start || 0,
        'total' => total
      }
    end
  end

  # This does what expander does, flattening the json doc into keys and values
  # so that solr can search them.
  class SolrDoc
    def initialize(json, id)
      @json = json
      @id = id
    end

    def [](key)
      values = matching_values { |match_key| match_key == key }
      values[0]
    end

    def matching_values(&block)
      result = {}
      key_values(nil, @json) do |key, value|
        if block.call(key)
          if result.has_key?(key)
            result[key] << value.to_s
          else
            result[key] = value.to_s.clone
          end
        end
      end
      # Handle manufactured value(s)
      if block.call('X_CHEF_id_CHEF_X')
        if result.has_key?('X_CHEF_id_CHEF_X')
          result['X_CHEF_id_CHEF_X'] << @id.to_s
        else
          result['X_CHEF_id_CHEF_X'] = @id.to_s.clone
        end
      end

      result.values
    end

    private

    def key_values(key_so_far, value, &block)
      if value.is_a?(Hash)
        value.each_pair do |child_key, child_value|
          block.call(child_key, child_value.to_s)
          if key_so_far
            new_key = "#{key_so_far}_#{child_key}"
            key_values(new_key, child_value, &block)
          else
            key_values(child_key, child_value, &block) if child_value.is_a?(Hash) || child_value.is_a?(Array)
          end
        end
      elsif value.is_a?(Array)
        value.each do |child_value|
          key_values(key_so_far, child_value, &block)
        end
      else
        block.call(key_so_far || 'text', value.to_s)
      end
    end
  end

  class SolrParser
    def initialize(query_string)
      @query_string = query_string
      @index = 0
    end

    def parse
      read_expression
    end

    #
    # Tokenization
    #
    def peek_token
      @next_token ||= parse_token
    end

    def next_token
      result = peek_token
      @next_token = nil
      result
    end

    def parse_token
      # Skip whitespace
      skip_whitespace
      return nil if eof?

      # Operators
      operator = peek_operator_token
      if operator
        @index+=operator.length
        operator
      else
        # Everything that isn't whitespace or an operator, is part of a term
        # (characters plus backslashed escaped characters)
        start_index = @index
        begin
          if @query_string[@index] == '\\'
            @index+=1
          end
          @index+=1 if !eof?
        end until eof? || @query_string[@index] =~ /\s/ || peek_operator_token
        @query_string[start_index..@index-1]
      end
    end

    def skip_whitespace
      if @query_string[@index] =~ /\s/
        whitespace = /\s+/.match(@query_string, @index)
        @index += whitespace[0].length
      end
    end

    def peek_operator_token
      if ['"', '+', '-', '!', '(', ')', '{', '}', '[', ']', '^', ':'].include?(@query_string[@index])
        return @query_string[@index]
      else
        result = @query_string[@index..@index+1]
        if ['&&', '||'].include?(result)
          return result
        end
      end
      nil
    end

    def eof?
      !@next_token && @index >= @query_string.length
    end

    # Parse tree creation
    def read_expression
      result = read_single_expression
      # Expression is over when we hit a close paren or eof
      # (peek_token has the side effect of skipping whitespace for us, so we
      # really know if we're at eof or not)
      until peek_token == ')' || eof?
        operator = peek_token
        if binary_operator?(operator)
          next_token
        else
          # If 2 terms are next to each other, the default operator is OR
          operator = 'OR'
        end
        next_expression = read_single_expression

        # Build the operator, taking precedence into account
        if result.is_a?(BinaryOperator) &&
           binary_operator_precedence(operator) > binary_operator_precedence(result.operator)
          # a+b*c -> a+(b*c)
          new_right = BinaryOperator.new(result.right, operator, next_expression)
          result = BinaryOperator.new(result.left, result.operator, new_right)
        else
          # a*b+c -> (a*b)+c
          result = BinaryOperator.new(result, operator, next_expression)
        end
      end
      result
    end

    def parse_error(token, str)
      error = "Error on token '#{token}' at #{@index} of '#{@query_string}': #{str}"
      puts error
      raise error
    end

    def read_single_expression
      token = next_token
      # If EOF, we have a problem Houston
      if !token
        parse_error(nil, "Expected expression!")

      # If it's an unary operand, build that
      elsif unary_operator?(token)
        operand = read_single_expression
        # TODO We rely on all unary operators having higher precedence than all
        # binary operators.  Check if this is the case.
        UnaryOperator.new(token, operand)

      # If it's the start of a phrase, read the terms in the phrase
      elsif token == '"'
        # Read terms until close "
        phrase_terms = []
        until (term = next_token) == '"'
          phrase_terms << Term.new(term)
        end
        Phrase.new(phrase_terms)

      # If it's the start of a range query, build that
      elsif token == '{' || token == '['
        left = next_token
        parse_error(left, "Expected left term in range query") if !left
        to = next_token
        parse_error(left, "Expected TO in range query") if to != "TO"
        right = next_token
        parse_error(right, "Expected left term in range query") if !right
        end_range = next_token
        parse_error(right, "Expected end range '#{expected_end_range}") if !['{', '['].include?(end_range)
        RangeQuery.new(left, right, token == '[', end_range == ']')

      elsif token == '('
        subquery = read_expression
        close_paren = next_token
        parse_error(close_paren, "Expected ')'") if close_paren != ')'
        Subquery.new(subquery)

      # If it's the end of a closure, raise an exception
      elsif ['}',']',')'].include?(token)
        parse_error(token, "Unexpected end paren")

      # If it's a binary operator, raise an exception
      elsif binary_operator?(token)
        parse_error(token, "Unexpected binary operator")

      # Otherwise it's a term.
      else
        Term.new(token)
      end
    end

    def unary_operator?(token)
      [ 'NOT', '+', '-' ].include?(token)
    end

    def binary_operator?(token)
      [ 'AND', 'OR', '^', ':'].include?(token)
    end

    def binary_operator_precedence(token)
      case token
      when '^'
        4
      when ':'
        3
      when 'AND'
        2
      when 'OR'
        1
      end
    end

    DEFAULT_FIELD = 'text'

    class RegexpableQuery
      def initialize(regexp_string, literal_string)
        @regexp_string = regexp_string
        # Surround the regexp with word boundaries
        @regexp = Regexp.new("(^|#{NON_WORD_CHARACTER})#{regexp_string}($|#{NON_WORD_CHARACTER})", true)
        @literal_string = literal_string
      end

      attr_reader :literal_string
      attr_reader :regexp_string
      attr_reader :regexp

      def matches_doc?(doc)
        value = doc[DEFAULT_FIELD]
        return value ? matches_values?([value]) : false
      end
      def matches_values?(values)
        values.any? { |value| !@regexp.match(value).nil? }
      end

      WORD_CHARACTER = "[A-Za-z0-9@._':]"
      NON_WORD_CHARACTER = "[^A-Za-z0-9@._':]"
    end

    class Term < RegexpableQuery
      def initialize(term)
        # Get rid of escape characters, turn * and ? into .* and . for regex, and
        # escape everything that needs escaping
        literal_string = ""
        regexp_string = ""
        index = 0
        while index < term.length
          if term[index] == '*'
            regexp_string << "#{WORD_CHARACTER}*"
            literal_string = nil
            index += 1
          elsif term[index] == '?'
            regexp_string << WORD_CHARACTER
            literal_string = nil
            index += 1
          elsif term[index] == '~'
            raise "~ unsupported"
          else
            if term[index] == '\\'
              index = index+1
              if index >= term.length
                raise "Backslash at end of string '#{term}'"
              end
            end
            literal_string << term[index] if literal_string
            regexp_string << Regexp.escape(term[index])
            index += 1
          end
        end
        super(regexp_string, literal_string)
      end

      def to_s
        "Term(#{regexp_string})"
      end
    end

    class Phrase < RegexpableQuery
      def initialize(terms)
        # Phrase is terms separated by whitespace
        if terms.size == 0 && terms[0].literal_string
          literal_string = terms[0].literal_string
        else
          literal_string = nil
        end
        super(terms.map { |term| term.regexp_string }.join("#{NON_WORD_CHARACTER}+"), literal_string)
      end

      def to_s
        "Phrase(\"#{@regexp_string}\")"
      end
    end

    class Subquery
      def initialize(subquery)
        @subquery = subquery
      end

      def to_s
        "(#{@subquery})"
      end

      def literal_string
        subquery.literal_string
      end

      def regexp
        subquery.regexp
      end

      def regexp_string
        subquery.regexp_string
      end

      def matches_doc?(doc)
        subquery.matches_doc?(doc)
      end

      def matches_values?(values)
        subquery.matches_values?(values)
      end
    end

    class RangeQuery
      def initialize(from, to, from_inclusive, to_inclusive)
        @from = from
        @to = to
        @from_inclusive = from_inclusive
        @to_inclusive = to_inclusive
      end

      def to_s
        "#{@from_inclusive ? '[' : '{'}#{@from} TO #{@to}#{@to_inclusive ? '[' : '{'}"
      end

      def matches?(key, value)
        case @from <=> value
        when -1
          return false
        when 0
          return false if !@from_inclusive
        end
        case @to <=> value
        when 1
          return false
        when 0
          return false if !@to_inclusive
        end
        return true
      end
    end

    class UnaryOperator
      def initialize(operator, operand)
        @operator = operator
        @operand = operand
      end

      def to_s
        "#{operator} #{operand}"
      end

      attr_reader :operator
      attr_reader :operand

      def matches_doc?(doc)
        case @operator
        when '-'
        when 'NOT'
          !operand.matches_doc?(doc)
        when '+'
          # TODO This operator uses relevance to eliminate other, unrelated
          # expressions.  +a OR b means "if it has b but not a, don't return it"
          raise "+ not supported yet, because it is hard."
        end
      end

      def matches_values?(values)
        case @operator
        when '-'
        when 'NOT'
          !operand.matches_values?(values)
        when '+'
          # TODO This operator uses relevance to eliminate other, unrelated
          # expressions.  +a OR b means "if it has b but not a, don't return it"
          raise "+ not supported yet, because it is hard."
        end
      end
    end

    class BinaryOperator
      def initialize(left, operator, right)
        @left = left
        @operator = operator
        @right = right
      end

      def to_s
        "(#{left} #{operator} #{right})"
      end

      attr_reader :left
      attr_reader :operator
      attr_reader :right

      def matches_doc?(doc)
        case @operator
        when 'AND'
          left.matches_doc?(doc) && right.matches_doc?(doc)
        when 'OR'
          left.matches_doc?(doc) || right.matches_doc?(doc)
        when '^'
          left.matches_doc?(doc)
        when ':'
          if left.respond_to?(:literal_string) && left.literal_string
            value = doc[left.literal_string]
            right.matches_values?([value])
          else
            values = doc.matching_values { |key| left.matches_values?([key]) }
            right.matches_values?(values)
          end
        end
      end

      def matches_values?(values)
        case @operator
        when 'AND'
          left.matches_values?(values) && right.matches_values?(values)
        when 'OR'
          left.matches_values?(values) || right.matches_values?(values)
        when '^'
          left.matches_values?(values)
        when ':'
          raise ": does not work inside a : or term"
        end
      end
    end
  end
end
