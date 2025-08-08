# Build stage
FROM golang:1.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o app

# Runtime stage
FROM gcr.io/distroless/base-debian12
COPY --from=build /src/app /app
EXPOSE 8080
ENTRYPOINT ["/app"]
