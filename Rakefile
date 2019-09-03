require 'bundler'
Bundler::GemHelper.install_tasks

require "rake/testtask"
require "rake/clean"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/test_*.rb"]
end

require "rake/extensiontask"

spec = eval File.read("certstore_c.gemspec")

Rake::ExtensionTask.new("certstore", spec) do |ext|
  ext.lib_dir = "lib/certstore"
end

CLEAN.include('lib/certstore/certstore.*')

task :default => [:clobber, :compile, :test]
