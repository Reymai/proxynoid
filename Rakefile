# frozen_string_literal: true

require 'rake/testtask'

Rake::TestTask.new do |task|
  task.libs << 'lib'
  task.test_files = FileList['test/*_test.rb']
  task.verbose = false
end

task default: :test
