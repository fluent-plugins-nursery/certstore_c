require "bundler/gem_tasks"
require "bundler/setup"
require "rake/testtask"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/test_*.rb"]
end

require "rake/extensiontask"

Rake::ExtensionTask.new("certstore") do |ext|
  ext.lib_dir = "lib/certstore"
end

task :default => [:clobber, :compile, :test]
