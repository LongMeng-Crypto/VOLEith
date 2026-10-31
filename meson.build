project(
  'VOLEith',
  ['c', 'cpp'],
  version: '0.1.0',
  meson_version: '>=0.59',
  default_options: ['cpp_std=c++20', 'warning_level=3'],
)

boost_test = dependency('boost', modules: ['unit_test_framework'])
openssl = dependency('openssl')
faest_includes = include_directories(
  'third_party/faest',
  'third_party/faest/sha3',
  'third_party/faest/sha3/opt64',
)

faest_vole_sources = files(
  'third_party/faest/aes.c',
  'third_party/faest/bavc.c',
  'third_party/faest/compat.c',
  'third_party/faest/fields.c',
  'third_party/faest/faest_aes_128.c',
  'third_party/faest/instances.c',
  'third_party/faest/random_oracle.c',
  'third_party/faest/universal_hashing.c',
  'third_party/faest/utils.c',
  'third_party/faest/vole.c',
  'third_party/faest/sha3/KeccakHash.c',
  'third_party/faest/sha3/KeccakSponge.c',
  'third_party/faest/sha3/opt64/KeccakP-1600-opt64.c',
)

faest_internal = static_library(
  'faest_vole_primitives',
  faest_vole_sources,
  include_directories: faest_includes,
  dependencies: openssl,
  c_args: ['-DFAEST_STATIC', '-DFAEST_EXPORT=', '-DFAEST_TESTS'],
)

backend_sources = files(
  'backend/binary_circuit.cpp',
  'backend/backend_witness.cpp',
  'backend/prepared_binary_circuit.cpp',
  'backend/circuit_format.cpp',
  'backend/json_circuit.cpp',
  'backend/security_parameters.cpp',
  'backend/quadratic_relation.cpp',
  'backend/vole/gf128.cpp',
  'backend/vole/bit_matrix_transpose.cpp',
  'backend/generic_quicksilver.cpp',
  'backend/generic_nizk.cpp',
  'backend/mixed_quadratic.cpp',
  'backend/vole/faest_vole.cpp',
  'backend/vole/quicksilver.cpp',
)

sha256_frontend_sources = files(
  'circuits/common/input_visibility.cpp',
  'circuits/sha2/sha256/faest_quicksilver.cpp',
  'circuits/sha2/sha256/nizk.cpp',
  'circuits/sha2/sha256/sha256_circuit.cpp',
  'circuits/sha2/sha256/witness.cpp',
)

sha2_64_frontend_sources = files(
  'circuits/sha2/sha512_family/sha512_family.cpp',
  'circuits/sha2/sha512_family/sha384_circuit.cpp',
  'circuits/sha2/sha512_family/sha512_circuit.cpp',
)

aes_frontend_sources = files(
  'circuits/aes/aes128_faest_circuit.cpp',
  'circuits/shake/shake256_circuit.cpp',
)

project_includes = include_directories('.', 'backend', 'backend/vole', 'circuits/sha2/sha256')

vole_sha256_lib = static_library(
  'vole_sha256',
  backend_sources + sha256_frontend_sources + sha2_64_frontend_sources + aes_frontend_sources,
  include_directories: [project_includes, faest_includes],
  link_with: faest_internal,
  dependencies: openssl,
)

vole_sha256_dep = declare_dependency(
  link_with: [vole_sha256_lib, faest_internal],
  include_directories: [project_includes, faest_includes],
  dependencies: openssl,
)

tests = executable(
  'vole_sha256_tests',
  files(
    'tests/binary_circuit.cpp',
    'tests/bit_matrix_transpose.cpp',
    'tests/aes_circuit.cpp',
    'tests/shake256_circuit.cpp',
    'tests/mixed_quadratic.cpp',
    'tests/main.cpp',
    'tests/faest_integration.cpp',
    'tests/fields.cpp',
    'tests/generic_backend.cpp',
    'tests/nizk.cpp',
    'tests/optimized_primitives.cpp',
    'tests/quicksilver.cpp',
    'tests/sha256_circuit.cpp',
    'tests/sha512_family_circuit.cpp',
    'tests/witness.cpp',
  ),
  dependencies: [vole_sha256_dep, boost_test],
  include_directories: faest_includes,
  cpp_args: ['-DBOOST_TEST_DYN_LINK', '-DFAEST_TESTS'],
)

executable(
  'vole-sha256',
  files('cli.cpp'),
  dependencies: [vole_sha256_dep, openssl],
  include_directories: faest_includes,
)

test('VOLEith', tests, timeout: 180)

executable('vole-shake256', 'circuits/shake/benchmark.cpp', dependencies: [vole_sha256_dep, openssl], include_directories: faest_includes)
