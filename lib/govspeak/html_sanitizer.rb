require "addressable/uri"

class Govspeak::HtmlSanitizer
  class ImageSourceWhitelister
    def initialize(allowed_image_hosts)
      @allowed_image_hosts = allowed_image_hosts
    end

    def call(sanitize_context)
      return unless sanitize_context[:node_name] == "img"

      node = sanitize_context[:node]
      image_uri = Addressable::URI.parse(node["src"])
      unless image_uri.relative? || @allowed_image_hosts.include?(image_uri.host)
        node.unlink # the node isn't sanitary. Remove it from the document.
      end
    end
  end

  class TableCellTextAlignWhitelister
    def call(sanitize_context)
      return unless %w[td th].include?(sanitize_context[:node_name])

      node = sanitize_context[:node]

      # Kramdown uses text-align to allow table cells to be aligned
      # http://kramdown.gettalong.org/quickref.html#tables
      if invalid_style_attribute?(node["style"])
        node.remove_attribute("style")
      end
    end

    def invalid_style_attribute?(style)
      style && !style.match(/^text-align:\s*(center|left|right)$/)
    end
  end

  class YoutubeTransformer
    def call(sanitize_context)
      node      = sanitize_context[:node]
      node_name = sanitize_context[:node_name]

      # Don't continue if this node is already allowlisted or is not an element.
      return if sanitize_context[:is_allowlisted] || !node.element?

      # Don't continue unless the node is an iframe.
      return unless node_name == "iframe"

      # Verify that the video URL is actually a valid YouTube video URL.
      return unless node["src"] =~ %r{\A(?:https?:)?//(?:www\.)?((youtube)|(youtu\.be))(?:-nocookie)?\.com/}

      # We're now certain that this is a YouTube embed, but we still need to run
      # it through a special Sanitize step to ensure that no unwanted elements or
      # attributes that don't belong in a YouTube embed can sneak in.
      Sanitize.node!(node, {
        elements: %w[iframe],

        attributes: {
          "iframe" => %w[allowfullscreen frameborder height src width title allow],
        },
      })

      # Now that we're sure that this is a valid YouTube embed and that there are
      # no unwanted elements or attributes hidden inside it, we can tell Sanitize
      # to allowlist the current node.
      { node_allowlist: [node] }
    end
  end

  def initialize(dirty_html, options = {})
    @dirty_html = dirty_html
    @allowed_image_hosts = options[:allowed_image_hosts]
  end

  def sanitize
    transformers = [TableCellTextAlignWhitelister.new, YoutubeTransformer.new]
    if @allowed_image_hosts && @allowed_image_hosts.any?
      transformers << ImageSourceWhitelister.new(@allowed_image_hosts)
    end
    Sanitize.clean(@dirty_html, Sanitize::Config.merge(sanitize_config, transformers: transformers))
  end

  def sanitize_config
    Sanitize::Config.merge(
      Sanitize::Config::RELAXED,
      elements: Sanitize::Config::RELAXED[:elements] + %w[govspeak-embed-attachment govspeak-embed-attachment-link svg path],
      attributes: {
        :all => Sanitize::Config::RELAXED[:attributes][:all] + %w[role aria-label],
        "a" => Sanitize::Config::RELAXED[:attributes]["a"] + [:data],
        "svg" => Sanitize::Config::RELAXED[:attributes][:all] + %w[xmlns width height viewbox focusable],
        "path" => Sanitize::Config::RELAXED[:attributes][:all] + %w[fill d],
        "div" => [:data],
        "th" => Sanitize::Config::RELAXED[:attributes]["th"] + %w[style],
        "td" => Sanitize::Config::RELAXED[:attributes]["td"] + %w[style],
        "govspeak-embed-attachment" => %w[content-id],
      },
    )
  end
end
