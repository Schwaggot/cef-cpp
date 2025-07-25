from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMakeToolchain, CMakeDeps


class CefCppConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeToolchain", "CMakeDeps"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    def requirements(self):
        self.requires("boost/1.88.0")

    def build_requirements(self):
        self.test_requires("gtest/1.16.0")

    def configure(self):
        # Configure Boost options for better compatibility
        self.options["boost"].shared = False
        self.options["boost"].header_only = False
        # Only build the components we need to speed up build
        self.options["boost"].without_atomic = False
        self.options["boost"].without_chrono = False
        self.options["boost"].without_container = False
        self.options["boost"].without_context = False
        self.options["boost"].without_coroutine = True
        self.options["boost"].without_date_time = False
        self.options["boost"].without_exception = False
        self.options["boost"].without_fiber = True
        self.options["boost"].without_filesystem = False
        self.options["boost"].without_graph = True
        self.options["boost"].without_iostreams = True
        self.options["boost"].without_json = True
        self.options["boost"].without_locale = True
        self.options["boost"].without_log = True
        self.options["boost"].without_math = True
        self.options["boost"].without_nowide = True
        self.options["boost"].without_program_options = True
        self.options["boost"].without_python = True
        self.options["boost"].without_random = True
        self.options["boost"].without_regex = False
        self.options["boost"].without_serialization = True
        self.options["boost"].without_stacktrace = True
        self.options["boost"].without_system = False
        self.options["boost"].without_test = True
        self.options["boost"].without_thread = False
        self.options["boost"].without_timer = True
        self.options["boost"].without_type_erasure = True
        self.options["boost"].without_wave = True
