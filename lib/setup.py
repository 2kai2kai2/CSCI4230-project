from setuptools import setup
from pybind11.setup_helpers import Pybind11Extension, build_ext

ext_modules = [
    Pybind11Extension(
        "cpp._cpplib",
        ["cpplib.cpp"]
    )
]
setup(cmdclass={"build_ext": build_ext}, ext_modules=ext_modules,
      name="cpp", 
      packages=["cpp"],
      package_dir={"cpp": "wrapper"},
      package_data={"cpp": ["*.pyi", "py.typed"]},
      include_package_data=True
)