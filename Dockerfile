FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /app

# Copy csproj and restore dependencies
COPY *.csproj ./
RUN dotnet restore

# Copy everything else and build
COPY . ./
RUN dotnet publish -c Release -o out --no-restore

# Build runtime image
FROM mcr.microsoft.com/dotnet/runtime:7.0
WORKDIR /app
COPY --from=build /app/out .

# Create a non-root user for security
RUN useradd -m aetherxss
USER aetherxss

# Run the application
ENTRYPOINT ["dotnet", "AetherXSS.dll"]