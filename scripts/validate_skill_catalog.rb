#!/usr/bin/env ruby
# Validates the canonical skill catalog under .agents/skills.

require "pathname"
require "psych"

SKILL_ROOT = Pathname(ARGV[0] || ".agents/skills")
PLACEHOLDER_DESCRIPTIONS = [
  "todo",
  "tbd",
  "n/a",
  "na",
  "placeholder",
  "coming soon"
].freeze

unless SKILL_ROOT.directory?
  warn "Skill root not found: #{SKILL_ROOT}"
  exit 1
end

errors = []
skill_names = Hash.new { |hash, key| hash[key] = [] }
checked = 0

SKILL_ROOT.children.select(&:directory?).sort.each do |skill_dir|
  skill_md = skill_dir / "SKILL.md"
  unless skill_md.file?
    errors << "#{skill_dir}: missing SKILL.md"
    next
  end

  checked += 1
  text = skill_md.read
  front_matter_match = text.match(/\A---\n(.*?)\n---\n/m)
  unless front_matter_match
    errors << "#{skill_md}: missing YAML front matter"
    next
  end

  begin
    metadata = Psych.safe_load(front_matter_match[1], permitted_classes: [], aliases: false)
  rescue Psych::Exception => e
    errors << "#{skill_md}: invalid YAML front matter (#{e.message.lines.first.strip})"
    next
  end

  unless metadata.is_a?(Hash)
    errors << "#{skill_md}: front matter must parse to a mapping"
    next
  end

  name = metadata["name"].to_s.strip
  description = metadata["description"].to_s.strip

  errors << "#{skill_md}: missing front matter field 'name'" if name.empty?
  errors << "#{skill_md}: missing front matter field 'description'" if description.empty?

  unless name.empty?
    skill_names[name] << skill_md.to_s
  end

  next if description.empty?

  normalized_description = description.downcase.gsub(/\s+/, " ").strip
  titleized_name = skill_dir.basename.to_s.split("-").map(&:capitalize).join(" ")
  if PLACEHOLDER_DESCRIPTIONS.include?(normalized_description) ||
     description == titleized_name ||
     description == metadata["name"].to_s.tr("-", " ")
    errors << "#{skill_md}: description is too vague for reliable discovery"
  end
end

skill_names.each do |name, paths|
  next if paths.length == 1

  errors << "duplicate skill name '#{name}' in #{paths.join(', ')}"
end

puts "Validated #{checked} skills in #{SKILL_ROOT}"

if errors.empty?
  puts "OK: metadata is valid, names are unique, and descriptions are usable."
  exit 0
end

warn "Found #{errors.length} validation issue(s):"
errors.each { |error| warn "- #{error}" }
exit 1
