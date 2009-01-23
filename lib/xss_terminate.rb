module XssTerminate
  def self.included(base)
    base.extend(ClassMethods)
    # sets up default of stripping tags for all fields
    base.send(:xss_terminate)
  end

  module ClassMethods
    def xss_terminate(options = {})
      before_validation :sanitize_fields

      write_inheritable_attribute(:xss_terminate_options, {})
      class_inheritable_reader :xss_terminate_options
      
      xss_terminate_options.default = XSS_TERMINATE_DEFAULT if defined?(XSS_TERMINATE_DEFAULT)
      xss_terminate_options.default = options.delete(:default) if options[:default]

      options.each do |method, attributes|
        attributes.each do |attr|
          xss_terminate_options[attr] = method
        end
      end
      
      include XssTerminate::InstanceMethods
    end
  end
  
  module InstanceMethods

    def sanitize_fields
      # fix a bug with Rails internal AR::Base models that get loaded before
      # the plugin, like CGI::Sessions::ActiveRecordStore::Session
      return if xss_terminate_options.nil?
      
      self.class.columns.each do |column|
        next unless (column.type == :string || column.type == :text)
        
        field = column.name.to_sym
        value = self[field]

        next if value.nil? or xss_terminate_options[field] == :except
        
        case xss_terminate_options[field]
        when :html5lib_sanitize
          self[field] = HTML5libSanitize.new.sanitize_html(value)
        when :sanitize
          self[field] = RailsSanitize.white_list_sanitizer.sanitize(value)
        else
          self[field] = RailsSanitize.full_sanitizer.sanitize(value)
        end
      end
      
    end
  end
end
