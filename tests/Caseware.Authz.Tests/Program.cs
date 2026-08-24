using System.Reflection;

namespace Caseware.Authz.Tests;

internal static class Program
{
    public static async Task<int> Main()
    {
        var failed = 0;
        var passed = 0;
        foreach (var type in typeof(Program).Assembly.GetTypes())
        {
            if (!type.IsClass || type.IsAbstract)
            {
                continue;
            }

            foreach (var method in type.GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly))
            {
                if (method.GetCustomAttribute<FactAttribute>() is null)
                {
                    continue;
                }

                var name = type.Name + "." + method.Name;
                try
                {
                    var instance = Activator.CreateInstance(type);
                    var result = method.Invoke(instance, null);
                    if (result is Task task)
                    {
                        await task.ConfigureAwait(false);
                    }

                    passed++;
                    Console.WriteLine("PASS " + name);
                }
                catch (Exception ex)
                {
                    failed++;
                    var inner = ex is TargetInvocationException tie ? tie.InnerException ?? ex : ex;
                    Console.WriteLine("FAIL " + name + ": " + inner);
                }
            }
        }

        Console.WriteLine($"{passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }
}
