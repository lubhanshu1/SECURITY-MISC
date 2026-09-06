#!/usr/bin/env ruby

ROOT = ARGV[0] || "."

files = Dir.glob(File.join(ROOT, "**", "*"), File::FNM_DOTMATCH)
            .select { |f| File.file?(f) }

extensions = Hash.new(0)

files.each do |file|
  ext = File.extname(file)
  ext = "(no extension)" if ext.empty?
  extensions[ext] += 1
end

puts "SECURITY-MISC Project Statistics"
puts "================================="
puts "Root: #{File.expand_path(ROOT)}"
puts "Files: #{files.length}"
puts
puts "Extensions:"

extensions.sort.each do |extension, count|
  puts "  #{extension.ljust(15)} #{count}"
end