newaction {
    trigger = "clean",
    description = "Remove all binaries and intermediate binaries, and vs files.",
    execute = function()
        print("Removing binaries, intermediate binaries and project files")
        os.rmdir(".build")
        os.rmdir("./build/bin")
        os.rmdir("./build/tmp")
        os.rmdir("./.vs")
        os.remove("**.sln")
        os.remove("**.vcxproj")
        os.remove("**.vcxproj.filters")
        os.remove("**.vcxproj.user")
        print("Done")
    end
}

workspace "ShellcodeLoader"
    location "build"
    configurations {"Debug", "Release"}
    architecture "x86"

outputdir = "%{cfg.buildcfg}-%{cfg.system}-%{cfg.architecture}"

project "ShellcodeLoader"
    kind "ConsoleApp" 
    language "C++"
    cppdialect "C++17"
    characterset "MBCS"

    files {
        "src/**.cpp",
    }

    links {
         "wininet",
         "winhttp",
         "psapi"
    }

    targetdir("build/bin/" .. outputdir .. "/%{prj.name}")
    objdir("build/tmp/" .. outputdir .. "/%{prj.name}")

    filter { "configurations:Debug" }
        defines { "DEBUG" }
        symbols "On"

    filter { "configurations:Release" }
        defines { "NDEBUG" }
        optimize "On"
        symbols "Off"                      