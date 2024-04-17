from setuptools import setup

if __name__ == "__main__":
    setup(
        name="seashell",
        version="0.0.1",
        description="Reverse shell generator utility",
        author="lil-skelly",
        license="LICENSE",
        package_dir={"": "src"},
        include_package_data=True,
    )
