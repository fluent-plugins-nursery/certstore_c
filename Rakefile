require 'bundler'
Bundler::GemHelper.install_tasks

require "rake/testtask"
require 'rake_compiler_dock'
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
  ext.cross_compile = true
  ext.lib_dir = File.join(*['lib', 'certstore', ENV['FAT_DIR']].compact)
  # cross_platform names are of MRI's platform name
  ext.cross_platform = ['x86-mingw32', 'x64-mingw32']
end


desc 'Build gems for Windows per rake-compiler-dock'
task 'gem:native' do
  # See RUBY_CC_VERSION in https://github.com/rake-compiler/rake-compiler-dock/blob/master/Dockerfile.mri
  RakeCompilerDock.sh <<-EOS
    bundle --local
    bundle exec rake cross native gem RUBY_CC_VERSION=2.4.0:2.5.0:2.6.0
EOS
end

CLEAN.include('lib/certstore/certstore.*')

task :default => [:clobber, :compile, :test]
