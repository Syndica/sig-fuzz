const std = @import("std");
const protobuf = @import("pb");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sig = b.dependency("sig", .{
        .target = target,
        .optimize = optimize,
        .@"enable-tsan" = false,
        .blockstore = .hashmap,
        .force_pic = true,
    });
    const pb = b.dependency("pb", .{
        .target = target,
        .optimize = optimize,
    });

    {
        const run_tests = b.step("test", "Run unit tests");

        const filters = b.option(
            []const []const u8,
            "filter",
            "List of filters, used for example to filter unit tests by name. " ++
                "Specified as a series like `-Dfilter='filter1' -Dfilter='filter2'`.",
        ) orelse &.{};

        const unit_tests_exe = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/lib.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "sig", .module = sig.module("sig") },
                    .{ .name = "protobuf", .module = pb.module("protobuf") },
                },
            }),
            .filters = filters,
        });

        const run = b.addRunArtifact(unit_tests_exe);
        run_tests.dependOn(&run.step);
    }

    var protoc_step = protobuf.RunProtocStep.create(b, pb.builder, target, .{
        .destination_directory = b.path("src/proto"),
        .source_files = &.{
            "protosol/proto/elf.proto",
            "protosol/proto/vm.proto",
            "protosol/proto/shred.proto",
            "protosol/proto/txn.proto",
        },
        .include_directories = &.{"protosol/proto"},
    });

    const lib = b.addLibrary(.{
        .name = "solfuzz_sig",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .omit_frame_pointer = false,
            .imports = &.{
                .{ .name = "sig", .module = sig.module("sig") },
                .{ .name = "protobuf", .module = pb.module("protobuf") },
            },
        }),
    });

    lib.root_module.fuzz = true;
    lib.step.dependOn(&protoc_step.step);
    b.installArtifact(lib);
}
