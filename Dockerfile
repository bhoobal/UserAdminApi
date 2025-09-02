# Build multi stage Dockerfile
# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

# copy csproj and restore as distinct layers
COPY *.csproj ./
RUN dotnet restore

# copy everything and build
COPY . .
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
COPY --from=build /app/publish .

# environment defaults
ENV ASPNETCORE_URLS=http://+:8080
ENV STORAGE_PROVIDER=json
EXPOSE 8080

ENTRYPOINT ["dotnet", "UserAdminApi.dll"]
