project(
  'vole-sha256',
  'cpp',
  version: '0.1.0',
  meson_version: '>=0.59',
  default_options: ['cpp_std=c++20', 'warning_level=3'],
)

boost_test = dependency('boost', modules: ['unit_test_framework'])
fs = import('fs')
cpp = meson.get_compiler('cpp')
faest_build_dir_option = get_option('faest_build_dir')
if fs.is_absolute(faest_build_dir_option)
  faest_build_dir = faest_build_dir_option
else
  faest_build_dir = join_paths(meson.project_source_root(), faest_build_dir_option)
endif
faest_internal = cpp.find_library('faest_no_random', dirs: faest_build_dir, static: true)
openssl = dependency('openssl')
faest_includes = include_directories('..', '../sha3', '../sha3/opt64')

vole_sha256_sources = files(
  'gf128.cpp',
  'faest_quicksilver.cpp',
  'faest_vole.cpp',
  'nizk.cpp',
  'quicksilver.cpp',
  'sha256_circuit.cpp',
  'witness.cpp',
)

vole_sha256_lib = static_library(
  'vole_sha256',
  vole_sha256_sources,
  include_directories: [include_directories('.'), faest_includes],
  dependencies: [faest_internal, openssl],
  cpp_args: ['-Wno-psabi'],
)

vole_sha256_dep = declare_dependency(
  link_with: vole_sha256_lib,
  include_directories: [include_directories('.'), faest_includes],
  dependencies: [faest_internal, openssl],
)

tests = executable(
  'vole_sha256_tests',
  files(
    'tests/main.cpp',
    'tests/faest_integration.cpp',
    'tests/nizk.cpp',
    'tests/quicksilver.cpp',
    'tests/sha256_circuit.cpp',
    'tests/witness.cpp',
  ),
  dependencies: [vole_sha256_dep, boost_test],
  include_directories: faest_includes,
  cpp_args: ['-DBOOST_TEST_DYN_LINK', '-Wno-psabi'],
)

executable(
  'vole-sha256',
  files('cli.cpp'),
  dependencies: [vole_sha256_dep, openssl],
  include_directories: faest_includes,
  cpp_args: ['-Wno-psabi'],
)

test('VOLE-SHA256', tests, timeout: 180)
