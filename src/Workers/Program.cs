using Microsoft.Extensions.Hosting;

// F0 host boundary. Delivery and outbox handlers will be introduced after review.
var builder = Host.CreateApplicationBuilder(args);
using var host = builder.Build();
await host.RunAsync();
