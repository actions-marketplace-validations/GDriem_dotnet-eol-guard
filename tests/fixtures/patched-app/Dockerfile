FROM mcr.microsoft.com/dotnet/sdk:10.0.401 AS build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0.13-noble-chiseled
COPY --from=build /app /app
ENTRYPOINT ["/app/Patched.Api"]
