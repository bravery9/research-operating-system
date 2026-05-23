from pathlib import Path

from invariant_os.analysis.detectors import detect_consumers, detect_entrypoints, detect_workers
from invariant_os.analysis.indexer import index_repository
from invariant_os.core.config import AuditConfig
from invariant_os.core.models import ConsumerType, EntrypointType, WorkerType

FIXTURES = Path(__file__).parent / "fixtures"


def _indexed_fixture(name: str):
    repo_root = FIXTURES / name
    return repo_root, index_repository(repo_root, AuditConfig())


def _indexed_tmp_repo(tmp_path: Path, files: dict[str, str]):
    for relative_path, content in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path, index_repository(tmp_path, AuditConfig())


def _assert_all_detections_have_evidence(detections):
    for detection in detections:
        assert detection.evidence
        for evidence in detection.evidence:
            assert evidence.file
            assert not evidence.file.startswith("/")
            assert evidence.line > 0
            assert evidence.pattern
            assert evidence.snippet


def _assert_unique_ids(detections):
    ids = [detection.id for detection in detections]
    assert len(ids) == len(set(ids))
    evidence_ids = [evidence.id for detection in detections for evidence in detection.evidence]
    assert len(evidence_ids) == len(set(evidence_ids))


def _has_evidence(detection, *, pattern: str, file: str | None = None):
    return any(
        evidence.pattern == pattern and (file is None or evidence.file == file)
        for evidence in detection.evidence
    )


def test_detects_express_route_queue_file_and_worker():
    repo_root, files = _indexed_fixture("mini_express_app")

    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)

    assert any(
        entrypoint.file == "app.js"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/import"
        and _has_evidence(entrypoint, pattern="express_route", file="app.js")
        for entrypoint in entrypoints
    )
    assert any(
        consumer.file == "app.js"
        and consumer.type == ConsumerType.QUEUE_OPERATION
        and consumer.pattern == "queue_operation"
        and _has_evidence(consumer, pattern="queue_operation", file="app.js")
        and "queue.add" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert any(
        consumer.file == "app.js"
        and consumer.type == ConsumerType.FILE_OPERATION
        and consumer.pattern == "file_operation"
        and _has_evidence(consumer, pattern="file_operation", file="app.js")
        and "fs.writeFile" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert any(
        worker.file == "worker.js"
        and worker.pattern == "queue_process"
        and _has_evidence(worker, pattern="queue_process", file="worker.js")
        and "queue.process" in worker.evidence[0].snippet
        for worker in workers
    )
    worker_file_pattern_pairs = [(worker.file, worker.pattern) for worker in workers]
    assert len(worker_file_pattern_pairs) == len(set(worker_file_pattern_pairs))
    combined_detections = [*entrypoints, *consumers, *workers]
    _assert_all_detections_have_evidence(combined_detections)
    _assert_unique_ids(entrypoints)
    _assert_unique_ids(consumers)
    _assert_unique_ids(workers)
    combined_evidence_ids = [
        evidence.id for detection in combined_detections for evidence in detection.evidence
    ]
    assert len(combined_evidence_ids) == len(set(combined_evidence_ids))


def test_enriches_express_route_with_static_handler_names(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.js": """
const express = require("express");
const app = express();
const router = express.Router();

app.post("/import", importHandler);
router.get("/reports", reports.list);
app.delete("/files/:id", async function deleteFile(req, res) {
  res.send("ok");
});
app.patch("/anonymous", (req, res) => res.send("ok"));
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    import_route = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.js" and entrypoint.route_path == "/import"
    )
    assert import_route.method == "post"
    assert import_route.handler == "importHandler"
    assert import_route.evidence[0].pattern == "express_route"

    reports_route = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.js" and entrypoint.route_path == "/reports"
    )
    assert reports_route.method == "get"
    assert reports_route.handler == "reports.list"
    assert reports_route.evidence[0].pattern == "express_route"

    delete_route = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.js" and entrypoint.route_path == "/files/:id"
    )
    assert delete_route.method == "delete"
    assert delete_route.handler == "deleteFile"
    assert delete_route.evidence[0].pattern == "express_route"

    anonymous_route = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.js" and entrypoint.route_path == "/anonymous"
    )
    assert anonymous_route.method == "patch"
    assert anonymous_route.handler is None
    assert anonymous_route.evidence[0].pattern == "express_route"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_nestjs_routes_with_controller_prefix_and_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/reports.controller.ts": """
import { Controller, Delete, Get, Post } from "@nestjs/common";

@Controller("api")
export class ReportsController {
  @Get("reports")
  listReports() {
    return [];
  }

  @Post("/imports")
  createImport() {
    return "ok";
  }

  @Delete(":id")
  deleteFile() {
    return "ok";
  }

  @Get(dynamicPath)
  ignored() {
    return "ignored";
  }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/reports.controller.ts" and entrypoint.route_path == "/api/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "ReportsController#listReports"
    assert reports.evidence[0].pattern == "nestjs_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/reports.controller.ts" and entrypoint.route_path == "/api/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "ReportsController#createImport"
    assert imports.evidence[0].pattern == "nestjs_route"

    deleted = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/reports.controller.ts" and entrypoint.route_path == "/api/:id"
    )
    assert deleted.method == "delete"
    assert deleted.handler == "ReportsController#deleteFile"
    assert deleted.evidence[0].pattern == "nestjs_route"

    assert not any(entrypoint.handler == "ReportsController#ignored" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_hapi_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "server.js": """
const Hapi = require("@hapi/hapi");
const server = Hapi.server({ port: 3000 });

server.route({ method: "GET", path: "/reports", handler: listReports });
server.route({ method: "POST", path: "/imports", handler: imports.create });
server.route({
  method: "DELETE",
  path: "/files/{id}",
  handler: FileController.delete,
});
server.route({ method: "GET", path: dynamicPath, handler: ignored });
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "server.js" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "listReports"
    assert reports.evidence[0].pattern == "hapi_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "server.js" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "imports.create"
    assert imports.evidence[0].pattern == "hapi_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "server.js" and entrypoint.route_path == "/files/{id}"
    )
    assert files.method == "delete"
    assert files.handler == "FileController.delete"
    assert files.evidence[0].pattern == "hapi_route"

    assert not any(entrypoint.handler == "ignored" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_go_http_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "server.go": """
package main

func main() {
    r.GET("/imports", importHandler)
    router.Post("/reports", reports.Create)
    http.HandleFunc("/health", healthHandler)
    mux.Handle("/assets/", fileServer)
    r.Delete("/anonymous", func(w http.ResponseWriter, r *http.Request) {})
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "server.go" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "get"
    assert imports.handler == "importHandler"
    assert imports.evidence[0].pattern == "go_route"

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "server.go" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "post"
    assert reports.handler == "reports.Create"
    assert reports.evidence[0].pattern == "go_route"

    health = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "server.go" and entrypoint.route_path == "/health"
    )
    assert health.method is None
    assert health.handler == "healthHandler"
    assert health.evidence[0].pattern == "go_route"

    assets = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "server.go" and entrypoint.route_path == "/assets/"
    )
    assert assets.method is None
    assert assets.handler == "fileServer"
    assert assets.evidence[0].pattern == "go_route"

    anonymous = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "server.go" and entrypoint.route_path == "/anonymous"
    )
    assert anonymous.method == "delete"
    assert anonymous.handler is None
    assert anonymous.evidence[0].pattern == "go_route"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_rails_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "config/routes.rb": """
Rails.application.routes.draw do
  get "/reports", to: "reports#index"
  post "/imports" => "imports#create"
  delete "/files/:id", to: "files#destroy"
  match "/search", to: "search#index", via: :post
  get dynamic_path, to: "ignored#index"
end
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "config/routes.rb" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "reports#index"
    assert reports.evidence[0].pattern == "rails_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "config/routes.rb" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "imports#create"
    assert imports.evidence[0].pattern == "rails_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "config/routes.rb" and entrypoint.route_path == "/files/:id"
    )
    assert files.method == "delete"
    assert files.handler == "files#destroy"
    assert files.evidence[0].pattern == "rails_route"

    search = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "config/routes.rb" and entrypoint.route_path == "/search"
    )
    assert search.method == "post"
    assert search.handler == "search#index"
    assert search.evidence[0].pattern == "rails_route"

    assert not any(entrypoint.handler == "ignored#index" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_sinatra_routes_with_static_methods(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.rb": """
require "sinatra"

get "/reports" do
  "ok"
end

post "/imports", &method(:create_import)

delete "/files/:id" do |id|
  "ok"
end

put dynamic_path do
  "ignored"
end
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.rb" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler is None
    assert reports.evidence[0].pattern == "sinatra_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.rb" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "create_import"
    assert imports.evidence[0].pattern == "sinatra_route"

    files_route = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.rb" and entrypoint.route_path == "/files/:id"
    )
    assert files_route.method == "delete"
    assert files_route.handler is None
    assert files_route.evidence[0].pattern == "sinatra_route"

    assert not any(entrypoint.route_path == "dynamic_path" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_laravel_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "routes/web.php": """
<?php

Route::get('/reports', [ReportController::class, 'index']);
Route::post('/imports', 'ImportController@store');
Route::delete('/files/{id}', [FileController::class, 'destroy']);
Route::match(['GET', 'POST'], '/search', [SearchController::class, 'index']);
Route::get($dynamicPath, 'IgnoredController@index');
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "routes/web.php" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "ReportController@index"
    assert reports.evidence[0].pattern == "laravel_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "routes/web.php" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "ImportController@store"
    assert imports.evidence[0].pattern == "laravel_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "routes/web.php" and entrypoint.route_path == "/files/{id}"
    )
    assert files.method == "delete"
    assert files.handler == "FileController@destroy"
    assert files.evidence[0].pattern == "laravel_route"

    search = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "routes/web.php" and entrypoint.route_path == "/search"
    )
    assert search.method is None
    assert search.handler == "SearchController@index"
    assert search.evidence[0].pattern == "laravel_route"

    assert not any(entrypoint.handler == "IgnoredController@index" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_aspnet_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "Controllers/ReportsController.cs": """
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/reports")]
public class ReportsController : ControllerBase
{
    [HttpGet("{id}")]
    public IActionResult Show() => Ok();

    [HttpPost("imports")]
    public IActionResult CreateImport() => Ok();

    [HttpDelete("/files/{id}")]
    public IActionResult DeleteFile() => Ok();

    [HttpPatch]
    public IActionResult PatchReport() => Ok();
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    show = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "Controllers/ReportsController.cs" and entrypoint.route_path == "/api/reports/{id}"
    )
    assert show.method == "get"
    assert show.handler == "ReportsController#Show"
    assert show.evidence[0].pattern == "aspnet_route"

    create = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "Controllers/ReportsController.cs" and entrypoint.route_path == "/api/reports/imports"
    )
    assert create.method == "post"
    assert create.handler == "ReportsController#CreateImport"
    assert create.evidence[0].pattern == "aspnet_route"

    delete = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "Controllers/ReportsController.cs" and entrypoint.route_path == "/files/{id}"
    )
    assert delete.method == "delete"
    assert delete.handler == "ReportsController#DeleteFile"
    assert delete.evidence[0].pattern == "aspnet_route"

    patch = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "Controllers/ReportsController.cs" and entrypoint.route_path == "/api/reports"
        and entrypoint.method == "patch"
    )
    assert patch.handler == "ReportsController#PatchReport"
    assert patch.evidence[0].pattern == "aspnet_route"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_rust_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/main.rs": """
use axum::{routing::{get, post}, Router};

fn app() -> Router {
    Router::new()
        .route("/reports", get(list_reports))
        .route("/imports", post(handlers::create_import))
        .route("/anonymous", delete(|| async {}))
}

#[get("/health")]
async fn health() -> impl Responder { "ok" }
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main.rs" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "list_reports"
    assert reports.evidence[0].pattern == "rust_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main.rs" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "handlers::create_import"
    assert imports.evidence[0].pattern == "rust_route"

    anonymous = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main.rs" and entrypoint.route_path == "/anonymous"
    )
    assert anonymous.method == "delete"
    assert anonymous.handler is None
    assert anonymous.evidence[0].pattern == "rust_route"

    health = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main.rs" and entrypoint.route_path == "/health"
    )
    assert health.method == "get"
    assert health.handler == "health"
    assert health.evidence[0].pattern == "rust_route"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_kotlin_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/main/kotlin/App.kt": """
import io.ktor.server.routing.*

fun Application.module() {
    routing {
        get("/reports", ::listReports)
        post("/imports") { createImport(call) }
        delete("/anonymous") { call.respondText("ok") }
    }
}

@GetMapping("/spring/reports")
fun springReports(): String = "ok"

@PostMapping("/spring/imports")
suspend fun springImport(): String = "ok"
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/kotlin/App.kt" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "listReports"
    assert reports.evidence[0].pattern == "kotlin_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/kotlin/App.kt" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler is None
    assert imports.evidence[0].pattern == "kotlin_route"

    spring_reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/kotlin/App.kt" and entrypoint.route_path == "/spring/reports"
    )
    assert spring_reports.method == "get"
    assert spring_reports.handler == "springReports"
    assert spring_reports.evidence[0].pattern == "kotlin_route"

    spring_import = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/kotlin/App.kt" and entrypoint.route_path == "/spring/imports"
    )
    assert spring_import.method == "post"
    assert spring_import.handler == "springImport"
    assert spring_import.evidence[0].pattern == "kotlin_route"

    anonymous = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/kotlin/App.kt" and entrypoint.route_path == "/anonymous"
    )
    assert anonymous.method == "delete"
    assert anonymous.handler is None
    assert anonymous.evidence[0].pattern == "kotlin_route"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_scala_play_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/routes": """
# Routes
GET     /reports            controllers.ReportController.index
POST    /imports            controllers.ImportController.create
DELETE  /files/:id          controllers.FileController.delete(id: Long)
GET     /ignored            dynamic.handler
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "conf/routes" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "controllers.ReportController.index"
    assert reports.evidence[0].pattern == "play_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "conf/routes" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "controllers.ImportController.create"
    assert imports.evidence[0].pattern == "play_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "conf/routes" and entrypoint.route_path == "/files/:id"
    )
    assert files.method == "delete"
    assert files.handler == "controllers.FileController.delete"
    assert files.evidence[0].pattern == "play_route"

    assert not any(entrypoint.handler == "dynamic.handler" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_phoenix_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "lib/demo_web/router.ex": """
defmodule DemoWeb.Router do
  use DemoWeb, :router

  scope "/api", DemoWeb do
    get "/reports", ReportController, :index
    post "/imports", ImportController, :create
    delete "/files/:id", FileController, :delete
    get dynamic_path, IgnoredController, :index
  end
end
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "lib/demo_web/router.ex" and entrypoint.route_path == "/api/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "DemoWeb.ReportController#index"
    assert reports.evidence[0].pattern == "phoenix_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "lib/demo_web/router.ex" and entrypoint.route_path == "/api/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "DemoWeb.ImportController#create"
    assert imports.evidence[0].pattern == "phoenix_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "lib/demo_web/router.ex" and entrypoint.route_path == "/api/files/:id"
    )
    assert files.method == "delete"
    assert files.handler == "DemoWeb.FileController#delete"
    assert files.evidence[0].pattern == "phoenix_route"

    assert not any(entrypoint.handler == "DemoWeb.IgnoredController#index" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_clojure_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/app/routes.clj": """
(ns app.routes
  (:require [compojure.core :refer [GET POST DELETE]]))

(defroutes app-routes
  (GET "/reports" [] reports/index)
  (POST "/imports" request imports/create)
  (DELETE "/files/:id" [] files.destroy/delete)
  (GET dynamic-path [] ignored/handler))
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/app/routes.clj" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "reports/index"
    assert reports.evidence[0].pattern == "clojure_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/app/routes.clj" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "imports/create"
    assert imports.evidence[0].pattern == "clojure_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/app/routes.clj" and entrypoint.route_path == "/files/:id"
    )
    assert files.method == "delete"
    assert files.handler == "files.destroy/delete"
    assert files.evidence[0].pattern == "clojure_route"

    assert not any(entrypoint.handler == "ignored/handler" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_haskell_servant_routes_with_static_methods(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/Api.hs": """
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}

module Api where

import Servant

type API =
       "reports" :> Get '[JSON] [Text]
  :<|> "imports" :> ReqBody '[JSON] Text :> Post '[JSON] Text
  :<|> "files" :> Capture "id" Int :> Delete '[JSON] NoContent
  :<|> DynamicPath :> Get '[JSON] Text
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/Api.hs" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler is None
    assert reports.evidence[0].pattern == "servant_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/Api.hs" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler is None
    assert imports.evidence[0].pattern == "servant_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/Api.hs" and entrypoint.route_path == "/files/{id}"
    )
    assert files.method == "delete"
    assert files.handler is None
    assert files.evidence[0].pattern == "servant_route"

    assert not any(entrypoint.route_path == "/DynamicPath" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_bottle_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.py": """
from bottle import route

@route("/reports")
def list_reports():
    return "ok"

@route("/imports", method="POST")
def create_import():
    return "ok"

@route("/files/<id>", method=["DELETE"])
def delete_file(id):
    return "ok"

@route(dynamic_path)
def ignored():
    return "ok"
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/reports"
    )
    assert reports.method is None
    assert reports.handler == "list_reports"
    assert reports.evidence[0].pattern == "bottle_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "create_import"
    assert imports.evidence[0].pattern == "bottle_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/files/<id>"
    )
    assert files.method == "delete"
    assert files.handler == "delete_file"
    assert files.evidence[0].pattern == "bottle_route"

    assert not any(entrypoint.handler == "ignored" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_pyramid_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.py": """
from pyramid.config import Configurator
from pyramid.view import view_config

@view_config(route_name="reports", request_method="GET")
def list_reports(request):
    return {}

@view_config(route_name="imports", request_method="POST")
def create_import(request):
    return {}

@view_config(route_name="dynamic", request_method="DELETE")
def ignored(request):
    return {}

config = Configurator()
config.add_route("reports", "/reports")
config.add_route(name="imports", pattern="/imports")
config.add_route("dynamic", dynamic_pattern)
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "pyramid"
        and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "list_reports"
    assert reports.evidence[0].pattern == "pyramid_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "pyramid"
        and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "create_import"
    assert imports.evidence[0].pattern == "pyramid_route"

    assert not any(
        entrypoint.framework_hint == "pyramid" and entrypoint.handler == "ignored"
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_starlette_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.py": """
from starlette.applications import Starlette
from starlette.routing import Route

routes = [
    Route("/reports", list_reports, methods=["GET"]),
    Route(path="/imports", endpoint=imports.create, methods=["POST"]),
    Route("/multi", multi_handler, methods=["GET", "POST"]),
    Route(dynamic_path, ignored, methods=["GET"]),
]

app = Starlette(routes=routes)
app.add_route("/files/{id}", delete_file, methods=["DELETE"])
app.add_route(dynamic_path, ignored)
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "starlette"
        and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "list_reports"
    assert reports.evidence[0].pattern == "starlette_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "starlette"
        and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "imports.create"
    assert imports.evidence[0].pattern == "starlette_route"

    multi = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "starlette"
        and entrypoint.route_path == "/multi"
    )
    assert multi.method is None
    assert multi.handler == "multi_handler"
    assert multi.evidence[0].pattern == "starlette_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "starlette"
        and entrypoint.route_path == "/files/{id}"
    )
    assert files.method == "delete"
    assert files.handler == "delete_file"
    assert files.evidence[0].pattern == "starlette_route"

    assert not any(
        entrypoint.framework_hint == "starlette" and entrypoint.handler == "ignored"
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_sanic_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.py": """
from sanic import Sanic

app = Sanic("demo")

@app.get("/reports")
async def list_reports(request):
    return []

@app.post("/imports")
def create_import(request):
    return "ok"

app.add_route(delete_file, "/files/<id>", methods=["DELETE"])
app.add_route(ignored, dynamic_path)
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "sanic"
        and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "list_reports"
    assert reports.evidence[0].pattern == "sanic_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "sanic"
        and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "create_import"
    assert imports.evidence[0].pattern == "sanic_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "sanic"
        and entrypoint.route_path == "/files/<id>"
    )
    assert files.method == "delete"
    assert files.handler == "delete_file"
    assert files.evidence[0].pattern == "sanic_route"

    assert not any(
        entrypoint.framework_hint == "sanic" and entrypoint.handler == "ignored"
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_tornado_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.py": """
import tornado.web

class ReportsHandler(tornado.web.RequestHandler):
    def get(self):
        self.write([])

class ImportHandler(tornado.web.RequestHandler):
    async def post(self):
        self.write("ok")

class FileHandler(tornado.web.RequestHandler):
    def delete(self, file_id):
        self.write("ok")

class IgnoredHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("ignored")

app = tornado.web.Application([
    (r"/reports", ReportsHandler),
    ("/imports", ImportHandler),
    (r"/files/([^/]+)", FileHandler),
    (dynamic_path, IgnoredHandler),
])
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "ReportsHandler#get"
    assert reports.evidence[0].pattern == "tornado_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "ImportHandler#post"
    assert imports.evidence[0].pattern == "tornado_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/files/([^/]+)"
    )
    assert files.method == "delete"
    assert files.handler == "FileHandler#delete"
    assert files.evidence[0].pattern == "tornado_route"

    assert not any(entrypoint.handler == "IgnoredHandler#get" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_aiohttp_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.py": """
from aiohttp import web

routes = web.RouteTableDef()

@routes.get("/reports")
async def list_reports(request):
    return web.json_response([])

@routes.post("/imports")
def create_import(request):
    return web.Response(text="ok")

app = web.Application()
app.router.add_delete("/files/{id}", delete_file)
app.router.add_get(dynamic_path, ignored)
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "list_reports"
    assert reports.evidence[0].pattern == "aiohttp_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "create_import"
    assert imports.evidence[0].pattern == "aiohttp_route"

    files = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py" and entrypoint.route_path == "/files/{id}"
    )
    assert files.method == "delete"
    assert files.handler == "delete_file"
    assert files.evidence[0].pattern == "aiohttp_route"

    assert not any(entrypoint.handler == "ignored" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_fastapi_file_and_network_consumers():
    repo_root, files = _indexed_fixture("mini_fastapi_app")

    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)

    assert any(
        entrypoint.file == "main.py"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/upload"
        and _has_evidence(entrypoint, pattern="fastapi_route", file="main.py")
        for entrypoint in entrypoints
    )
    assert any(
        consumer.file == "main.py"
        and consumer.type == ConsumerType.NETWORK_OPERATION
        and consumer.pattern == "network_operation"
        and "requests.get" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert any(
        consumer.file == "main.py"
        and consumer.type == ConsumerType.FILE_OPERATION
        and consumer.pattern == "file_operation"
        and "open(" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    _assert_all_detections_have_evidence([*entrypoints, *consumers])
    _assert_unique_ids(entrypoints)
    _assert_unique_ids(consumers)


def test_enriches_fastapi_route_with_following_handler(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "main.py": """
from fastapi import FastAPI

app = FastAPI()

@app.post("/upload")
async def upload_file(request):
    return {"ok": True}

@app.get("/reports")
def list_reports():
    return []
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    upload = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "main.py"
        and entrypoint.framework_hint == "fastapi"
        and entrypoint.route_path == "/upload"
    )
    assert upload.method == "post"
    assert upload.handler == "upload_file"
    assert upload.evidence[0].pattern == "fastapi_route"

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "main.py"
        and entrypoint.framework_hint == "fastapi"
        and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "list_reports"
    assert reports.evidence[0].pattern == "fastapi_route"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_enriches_flask_route_with_handler_and_single_static_method(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.py": """
from flask import Flask

app = Flask(__name__)

@app.route("/preview", methods=["POST"])
def preview():
    return "ok"

@app.route("/health")
def health():
    return "ok"
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    preview = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "flask"
        and entrypoint.route_path == "/preview"
    )
    assert preview.method == "post"
    assert preview.handler == "preview"
    assert preview.evidence[0].pattern == "flask_route"

    health = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "flask"
        and entrypoint.route_path == "/health"
    )
    assert health.method is None
    assert health.handler == "health"
    assert health.evidence[0].pattern == "flask_route"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_leaves_flask_method_none_when_methods_are_ambiguous(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "app.py": """
from flask import Flask

app = Flask(__name__)

@app.route("/multi", methods=["GET", "POST"])
def multi():
    return "ok"

@app.route("/dynamic", methods=allowed_methods)
def dynamic():
    return "ok"
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    multi = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "flask"
        and entrypoint.route_path == "/multi"
    )
    assert multi.method is None
    assert multi.handler == "multi"

    dynamic = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "app.py"
        and entrypoint.framework_hint == "flask"
        and entrypoint.route_path == "/dynamic"
    )
    assert dynamic.method is None
    assert dynamic.handler == "dynamic"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_template_consumer_and_route():
    repo_root, files = _indexed_fixture("mini_template_app")

    entrypoints = detect_entrypoints(repo_root, files)
    consumers = detect_consumers(repo_root, files)

    assert any(
        entrypoint.file == "app.py"
        and entrypoint.route_path == "/preview"
        and _has_evidence(entrypoint, pattern="flask_route", file="app.py")
        for entrypoint in entrypoints
    )
    assert any(
        consumer.file == "app.py"
        and consumer.type == ConsumerType.TEMPLATE_OPERATION
        and consumer.pattern == "template_operation"
        and "render_template" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    _assert_all_detections_have_evidence([*entrypoints, *consumers])
    _assert_unique_ids(entrypoints)
    _assert_unique_ids(consumers)


def test_detects_tomcat_web_xml_entrypoints():
    repo_root, files = _indexed_fixture("mini_tomcat_app")

    entrypoints = detect_entrypoints(repo_root, files)

    assert any(
        entrypoint.file == "WEB-INF/web.xml"
        and entrypoint.framework_hint == "tomcat-web-xml"
        and entrypoint.route_path == "/*"
        and _has_evidence(entrypoint, pattern="tomcat_url_pattern", file="WEB-INF/web.xml")
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.file == "WEB-INF/web.xml"
        and entrypoint.framework_hint == "tomcat-web-xml"
        and entrypoint.route_path == "/api/*"
        and _has_evidence(entrypoint, pattern="tomcat_url_pattern", file="WEB-INF/web.xml")
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.file == "WEB-INF/web.xml"
        and entrypoint.framework_hint == "tomcat-web-xml"
        and entrypoint.evidence[0].pattern == "tomcat_filter_class"
        and "SecurityFilter" in entrypoint.evidence[0].snippet
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.file == "WEB-INF/web.xml"
        and entrypoint.framework_hint == "tomcat-web-xml"
        and entrypoint.evidence[0].pattern == "tomcat_servlet_class"
        and "RestDispatcher" in entrypoint.evidence[0].snippet
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_multiline_conf_tomcat_web_xml_and_security_constraints(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/web.xml": """
<web-app>
  <servlet>
    <servlet-name>LegacyDispatcher</servlet-name>
    <servlet-class>
      com.example.web.LegacyDispatcher
    </servlet-class>
  </servlet>
  <servlet-mapping>
    <servlet-name>LegacyDispatcher</servlet-name>
    <url-pattern>
      /legacy/*
    </url-pattern>
  </servlet-mapping>
  <security-constraint>
    <web-resource-collection>
      <url-pattern>/admin/*</url-pattern>
      <http-method>TRACE</http-method>
    </web-resource-collection>
  </security-constraint>
</web-app>
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert any(
        entrypoint.file == "conf/web.xml"
        and entrypoint.framework_hint == "tomcat-web-xml"
        and entrypoint.route_path == "/legacy/*"
        and _has_evidence(entrypoint, pattern="tomcat_url_pattern", file="conf/web.xml")
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.file == "conf/web.xml"
        and entrypoint.framework_hint == "tomcat-web-xml"
        and entrypoint.evidence[0].pattern == "tomcat_servlet_class"
        and "LegacyDispatcher" in entrypoint.evidence[0].snippet
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.file == "conf/web.xml"
        and entrypoint.framework_hint == "tomcat-security-constraint"
        and entrypoint.method == "trace"
        and entrypoint.route_path == "/admin/*"
        and _has_evidence(entrypoint, pattern="tomcat_security_constraint", file="conf/web.xml")
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_tomcat_server_connectors(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/server.xml": """
<Server>
  <Service name="Catalina">
    <Connector
      port="8081"
      protocol="HTTP/1.1"
      allowTrace="false"
      redirectPort="8444" />
    <Connector port="8444" scheme="https" secure="true" clientAuth="want" sslEnabledProtocols="TLSv1.2,TLSv1.3" />
  </Service>
</Server>
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert any(
        entrypoint.file == "conf/server.xml"
        and entrypoint.framework_hint == "tomcat-connector"
        and entrypoint.route_path == "http://*:8081"
        and entrypoint.evidence[0].message is not None
        and "allowTrace=false" in entrypoint.evidence[0].message
        and "redirectPort=8444" in entrypoint.evidence[0].message
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.file == "conf/server.xml"
        and entrypoint.framework_hint == "tomcat-connector"
        and entrypoint.route_path == "https://*:8444"
        and entrypoint.evidence[0].message is not None
        and "clientAuth=want" in entrypoint.evidence[0].message
        and "sslEnabledProtocols=TLSv1.2,TLSv1.3" in entrypoint.evidence[0].message
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_zsec_security_xml_url_rules_and_ignores_comments(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/security-common.xml": """
<security>
  <!-- <url path="/disabled" method="GET" authentication="optional" /> -->
  <url path="/reports/export" method="POST" authentication="required" csrf="true">
    <param name="exportType" regex="alpha" max-len="32" />
    <throttle name="exportThrottle" duration="60" threshold="5" />
  </url>
</security>
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert not any(entrypoint.route_path == "/disabled" for entrypoint in entrypoints)
    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "conf/security-common.xml"
        and entrypoint.framework_hint == "zsec-security"
        and entrypoint.route_path == "/reports/export"
    )
    assert match.method == "post"
    assert match.evidence[0].message is not None
    assert "authentication=required" in match.evidence[0].message
    assert "csrf=true" in match.evidence[0].message
    assert "param=exportType" in match.evidence[0].message
    assert "throttle=exportThrottle" in match.evidence[0].message
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_zsec_security_xml_control_consumers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/security-defaultrequestheaders.xml": """
<security>
  <default-request-headers>
    <header name="X-Forwarded-For" />
    <cookie name="JSESSIONID" />
  </default-request-headers>
</security>
""",
            "conf/security-safeheaders.xml": """
<security>
  <safe-response-headers>
    <header name="Strict-Transport-Security" />
  </safe-response-headers>
</security>
""",
            "conf/security-common.xml": """
<security>
  <content-types><content-type name="application/json" /></content-types>
  <url-validator name="externalUrl" />
  <xsspattern name="html" />
  <zip-sanitizer name="archives" />
</security>
""",
        },
    )

    consumers = detect_consumers(repo_root, files)

    assert any(
        consumer.file == "conf/security-defaultrequestheaders.xml"
        and consumer.type == ConsumerType.CONFIG_OPERATION
        and consumer.pattern == "zsec_security_control"
        and consumer.evidence[0].message is not None
        and "default-request-headers" in consumer.evidence[0].message
        and "header=X-Forwarded-For" in consumer.evidence[0].message
        and "cookie=JSESSIONID" in consumer.evidence[0].message
        for consumer in consumers
    )
    assert any(
        consumer.file == "conf/security-common.xml"
        and consumer.type == ConsumerType.ARCHIVE_OPERATION
        and consumer.pattern == "zsec_zip_sanitizer"
        and consumer.evidence[0].message is not None
        and "zip-sanitizer=archives" in consumer.evidence[0].message
        for consumer in consumers
    )
    assert any(
        consumer.file == "conf/security-common.xml"
        and consumer.type == ConsumerType.CONFIG_OPERATION
        and consumer.pattern == "zsec_security_control"
        and consumer.evidence[0].message is not None
        and "url-validator=externalUrl" in consumer.evidence[0].message
        and "xsspattern=html" in consumer.evidence[0].message
        for consumer in consumers
    )
    _assert_all_detections_have_evidence(consumers)
    _assert_unique_ids(consumers)


def test_detects_product_api_xml_mappings_with_auth_and_params(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/adsf/ADSProductAPIs.xml": """
<Rows>
  <ADSProductAPIs API_NAME="ExportReport" API_URL="/ads/export" MTCALL_NAME="methodToCall"
      MTCALL_VALUE="exportReport" SERVLET_CLASS_NAME="com.example.ExportServlet"
      IS_HS_REQUIRED="true" IS_ALLOWED_ON_DEMO="false" />
  <ADSProductAPIParams API_NAME="ExportReport" PARAM_NAME="domain" />
</Rows>
""",
            "conf/rmpdb/RMPProductAPIs.xml": """
<Rows>
  <RMPProductAPIs API_NAME="DeviceList" API_URL="/rmp/devices" MTCALL_NAME="operation"
      MTCALL_VALUE="listDevices" REQUIRES_ACCOUNT_AUTHORIZATION="true" ACCESS_TYPE="admin" />
</Rows>
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    ads_match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "conf/adsf/ADSProductAPIs.xml"
        and entrypoint.framework_hint == "product-api-xml"
        and entrypoint.route_path == "/ads/export"
    )
    assert ads_match.handler == "com.example.ExportServlet"
    assert ads_match.evidence[0].message is not None
    assert "MTCALL_NAME=methodToCall" in ads_match.evidence[0].message
    assert "MTCALL_VALUE=exportReport" in ads_match.evidence[0].message
    assert "IS_HS_REQUIRED=true" in ads_match.evidence[0].message
    assert "IS_ALLOWED_ON_DEMO=false" in ads_match.evidence[0].message
    assert "param=domain" in ads_match.evidence[0].message

    rmp_match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "conf/rmpdb/RMPProductAPIs.xml"
        and entrypoint.framework_hint == "product-api-xml"
        and entrypoint.route_path == "/rmp/devices"
    )
    assert rmp_match.handler == "listDevices"
    assert rmp_match.evidence[0].message is not None
    assert "REQUIRES_ACCOUNT_AUTHORIZATION=true" in rmp_match.evidence[0].message
    assert "ACCESS_TYPE=admin" in rmp_match.evidence[0].message
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_servlet_forward_config_mappings(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "WEB-INF/Servlet-Forward-Config.xml": """
<servlet-forward>
  <request url="/legacy/report.do" forward="/jsp/report.jsp" servlet="ReportForwardServlet" />
</servlet-forward>
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "WEB-INF/Servlet-Forward-Config.xml"
        and entrypoint.framework_hint == "servlet-forward-config"
        and entrypoint.route_path == "/legacy/report.do"
    )
    assert match.handler == "ReportForwardServlet"
    assert match.evidence[0].message is not None
    assert "forward=/jsp/report.jsp" in match.evidence[0].message
    assert "servlet=ReportForwardServlet" in match.evidence[0].message
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_deduplicates_same_enterprise_entrypoint_and_merges_evidence(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/web.xml": """
<web-app>
  <servlet-mapping><url-pattern>/api/*</url-pattern></servlet-mapping>
  <filter-mapping><url-pattern>/api/*</url-pattern></filter-mapping>
</web-app>
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    matches = [
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.framework_hint == "tomcat-web-xml"
        and entrypoint.route_path == "/api/*"
        and entrypoint.method is None
        and entrypoint.handler is None
    ]
    assert len(matches) == 1
    assert len(matches[0].evidence) == 2
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_adap_rest_api_xml_mappings():
    repo_root, files = _indexed_fixture("mini_tomcat_app")

    entrypoints = detect_entrypoints(repo_root, files)

    expected_routes = {"/report/getReportData", "/object/classObjects"}
    detected_routes = {
        entrypoint.route_path
        for entrypoint in entrypoints
        if entrypoint.file == "conf/adap/rest-api.xml"
        and entrypoint.framework_hint == "adap-rest-api"
        and _has_evidence(
            entrypoint, pattern="adap_rest_api_mapping", file="conf/adap/rest-api.xml"
        )
    }
    assert expected_routes <= detected_routes
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_adap_rest_api_multiline_metadata_and_ignores_comments(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/adap/rest-api.xml": """
<Rows>
  <!-- <ADAPRestApiMapping URL_PATH="/disabled" CLASS_NAME="example.Disabled" METHOD_NAME="run" /> -->
  <ADAPRestApiMapping
      TAB_NAME="reports"
      URL_PATH="/report/data"
      CLASS_NAME="com.example.ReportHandler"
      METHOD_NAME="getData"
      ACCESS_ID="REPORT_READ"
      ACCESS_TYPE="read" />
</Rows>
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert not any(entrypoint.route_path == "/disabled" for entrypoint in entrypoints)
    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "conf/adap/rest-api.xml"
        and entrypoint.framework_hint == "adap-rest-api"
        and entrypoint.route_path == "/report/data"
    )
    assert match.handler == "com.example.ReportHandler#getData"
    assert match.evidence[0].message is not None
    assert "ACCESS_ID=REPORT_READ" in match.evidence[0].message
    assert "ACCESS_TYPE=read" in match.evidence[0].message
    assert "TAB_NAME=reports" in match.evidence[0].message
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_taskengine_workers():
    repo_root, files = _indexed_fixture("mini_tomcat_app")

    workers = detect_workers(repo_root, files)

    assert any(
        worker.file == "conf/adap/taskflow.xml"
        and worker.framework_hint == "taskengine"
        and worker.pattern == "taskengine_task"
        and _has_evidence(worker, pattern="taskengine_task", file="conf/adap/taskflow.xml")
        and "EventUpdateTask" in worker.evidence[0].snippet
        for worker in workers
    )
    assert any(
        worker.file == "conf/adap/taskflow.xml"
        and worker.framework_hint == "taskengine"
        and worker.pattern == "taskengine_task"
        and "ImportLogTask" in worker.evidence[0].snippet
        for worker in workers
    )
    _assert_all_detections_have_evidence(workers)
    _assert_unique_ids(workers)


def test_detects_multiline_taskengine_workers_with_metadata(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/adap/taskflow.xml": """
<Rows>
  <!-- <TaskEngine_Task task_name="Disabled" class_name="example.DisabledTask" /> -->
  <TaskEngine_Task
      task_name="ImportLogSchedule"
      class_name="com.example.importlog.ImportLogTask" />
</Rows>
""",
        },
    )

    workers = detect_workers(repo_root, files)

    assert not any("DisabledTask" in worker.evidence[0].snippet for worker in workers)
    match = next(
        worker
        for worker in workers
        if worker.file == "conf/adap/taskflow.xml"
        and worker.framework_hint == "taskengine"
        and worker.pattern == "taskengine_task"
        and "ImportLogTask" in worker.evidence[0].snippet
    )
    assert match.evidence[0].message is not None
    assert "task_name=ImportLogSchedule" in match.evidence[0].message
    assert "class_name=com.example.importlog.ImportLogTask" in match.evidence[0].message
    _assert_all_detections_have_evidence(workers)
    _assert_unique_ids(workers)


def test_detects_java_spark_routes_with_static_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/main/java/App.java": """
import static spark.Spark.*;

public class App {
    public static void main(String[] args) {
        get("/reports", ReportController::list);
        post("/imports", ImportController::create);
        delete("/files/:id", (request, response) -> "ok");
        put(dynamicPath, ImportController::ignored);
    }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/java/App.java" and entrypoint.route_path == "/reports"
    )
    assert reports.method == "get"
    assert reports.handler == "ReportController::list"
    assert reports.evidence[0].pattern == "spark_route"

    imports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/java/App.java" and entrypoint.route_path == "/imports"
    )
    assert imports.method == "post"
    assert imports.handler == "ImportController::create"
    assert imports.evidence[0].pattern == "spark_route"

    files_route = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/java/App.java" and entrypoint.route_path == "/files/:id"
    )
    assert files_route.method == "delete"
    assert files_route.handler is None
    assert files_route.evidence[0].pattern == "spark_route"

    assert not any(entrypoint.handler == "ImportController::ignored" for entrypoint in entrypoints)
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_java_webservlet_jaxrs_and_soap_entrypoints(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/com/example/AnnotatedEndpoints.java": """
package com.example;

@WebServlet(value={"/servlet/report", "/servlet/export"})
class ReportServlet {}

@Path("/api")
class ReportResource {
    @GET
    @Path("/reports")
    public String listReports() { return "ok"; }

    @POST
    @Path("/reports")
    public String createReport() { return "ok"; }
}

@WebService
class AuditSoapService {
    @WebMethod
    public void syncAudit() {}
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert any(
        entrypoint.framework_hint == "java-webservlet"
        and entrypoint.route_path == "/servlet/report"
        and entrypoint.handler == "ReportServlet"
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.framework_hint == "jax-rs"
        and entrypoint.method == "get"
        and entrypoint.route_path == "/api/reports"
        and entrypoint.handler == "ReportResource#listReports"
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.framework_hint == "jax-rs"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/api/reports"
        and entrypoint.handler == "ReportResource#createReport"
        for entrypoint in entrypoints
    )
    assert any(
        entrypoint.type == EntrypointType.RPC_HANDLER
        and entrypoint.framework_hint == "java-soap"
        and entrypoint.handler == "AuditSoapService#syncAudit"
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_legacy_java_handler_class_candidates(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/com/example/LegacyReportController.java": """
package com.example;

class LegacyReportController {
    public void execute() {}
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert any(
        entrypoint.framework_hint == "java-enterprise-handler"
        and entrypoint.handler == "LegacyReportController"
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_javascript_and_cc_url_config_routes(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "webapps/adap/static/config.js": """
const apiUrl = "/TFAConfigDiv.cc?methodToCall=load";
const label = "/not/a/route";
""",
            "webapps/adap/static/legacy.cc": """
var mapping = "/legacy/report.do?methodToCall=save";
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    routes = {
        entrypoint.route_path
        for entrypoint in entrypoints
        if entrypoint.framework_hint == "javascript-url-config"
    }
    assert "/TFAConfigDiv.cc?methodToCall=load" in routes
    assert "/legacy/report.do?methodToCall=save" in routes
    assert "/not/a/route" not in routes
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)


def test_detects_nextjs_pages_and_app_api_routes(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "pages/api/import.ts": "export default function handler(req, res) { res.status(200).end(); }\n",
            "pages/api/users/[id].ts": "export default function handler(req, res) { res.status(200).end(); }\n",
            "app/api/import/route.ts": "export async function POST(request: Request) { return Response.json({ ok: true }); }\n",
            "app/api/reports/[...slug]/route.ts": "export function GET(request: Request) { return Response.json({ ok: true }); }\n",
            "app/api/search/[[...terms]]/route.ts": "export async function DELETE(request: Request) { return Response.json({ ok: true }); }\n",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    expected_routes = {
        "pages/api/import.ts": ("/api/import", None),
        "pages/api/users/[id].ts": ("/api/users/{id}", None),
        "app/api/import/route.ts": ("/api/import", "post"),
        "app/api/reports/[...slug]/route.ts": ("/api/reports/{slug}", "get"),
        "app/api/search/[[...terms]]/route.ts": ("/api/search/{terms}", "delete"),
    }
    for expected_file, (expected_route, expected_method) in expected_routes.items():
        match = next(
            entrypoint for entrypoint in entrypoints if entrypoint.file == expected_file
        )
        assert match.type == EntrypointType.HTTP_ROUTE
        assert match.line == 1
        assert match.method == expected_method
        assert match.route_path == expected_route
        assert match.evidence[0].file == expected_file
        assert match.evidence[0].line == 1
        assert match.evidence[0].pattern == "next_api_route"
        assert match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_generic_webhook_entrypoint(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"handlers/webhook.py": "def webhook(request):\n    return Response(status=204)\n"},
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "handlers/webhook.py" and entrypoint.type == EntrypointType.WEBHOOK
    )
    assert match.line == 1
    assert match.evidence[0].file == "handlers/webhook.py"
    assert match.evidence[0].line == 1
    assert match.evidence[0].pattern == "generic_webhook"
    assert "webhook" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_generic_graphql_resolver_mutation_and_query(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "schema.ts": "const resolver = {};\nexport const Mutation = {};\nexport const Query = {};\n"
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    expected = [
        ("resolver", 1, "resolver"),
        ("Mutation", 2, "Mutation"),
        ("Query", 3, "Query"),
    ]
    for _, line, snippet_part in expected:
        match = next(
            entrypoint
            for entrypoint in entrypoints
            if entrypoint.file == "schema.ts"
            and entrypoint.type == EntrypointType.GRAPHQL_RESOLVER
            and entrypoint.line == line
        )
        assert match.evidence[0].file == "schema.ts"
        assert match.evidence[0].line == line
        assert match.evidence[0].pattern == "generic_graphql"
        assert snippet_part in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_required_consumer_categories(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "ops.py": "subprocess.run(['convert', filename])\njson.loads(payload)\nsettings = yaml.safe_load(raw_config)\narchive.extractall(target_dir)\nparsed = parse(user_supplied_text)\n",
        },
    )

    consumers = detect_consumers(repo_root, files)

    expected = [
        (ConsumerType.PROCESS_OPERATION, "process_operation", 1, "subprocess.run"),
        (ConsumerType.DESERIALIZATION, "deserialization", 2, "json.loads"),
        (ConsumerType.CONFIG_OPERATION, "config_operation", 3, "settings"),
        (ConsumerType.ARCHIVE_OPERATION, "archive_operation", 4, "extractall"),
        (ConsumerType.PARSER_OPERATION, "parser_operation", 5, "parse("),
    ]
    for consumer_type, pattern, line, snippet_part in expected:
        match = next(
            consumer
            for consumer in consumers
            if consumer.file == "ops.py"
            and consumer.type == consumer_type
            and consumer.pattern == pattern
            and consumer.line == line
        )
        assert match.evidence[0].file == "ops.py"
        assert match.evidence[0].line == line
        assert match.evidence[0].pattern == pattern
        assert snippet_part in match.evidence[0].snippet
    _assert_all_detections_have_evidence(consumers)



def test_detects_java_enterprise_consumers():
    repo_root, files = _indexed_fixture("mini_tomcat_app")

    consumers = detect_consumers(repo_root, files)

    expected = [
        (ConsumerType.PARSER_OPERATION, "request_parameter", "getParameter"),
        (ConsumerType.PROCESS_OPERATION, "process_operation", "Runtime.getRuntime().exec"),
        (ConsumerType.PROCESS_OPERATION, "process_operation", "ProcessBuilder"),
        (ConsumerType.FILE_OPERATION, "file_operation", "Paths.get"),
        (ConsumerType.FILE_OPERATION, "file_operation", "Files.readAllBytes"),
        (ConsumerType.FILE_OPERATION, "file_operation", "Files.write"),
        (ConsumerType.DESERIALIZATION, "deserialization", "ObjectInputStream"),
        (ConsumerType.PARSER_OPERATION, "parser_operation", "DocumentBuilderFactory"),
        (ConsumerType.CONFIG_OPERATION, "config_operation", "properties.load"),
        (ConsumerType.DATABASE_OPERATION, "database_operation", "RelationalAPI"),
        (ConsumerType.DATABASE_OPERATION, "database_operation", "DriverManager.getConnection"),
        (ConsumerType.DIRECTORY_OPERATION, "directory_operation", "InitialDirContext"),
        (ConsumerType.DIRECTORY_OPERATION, "directory_operation", "context.search"),
    ]
    for consumer_type, pattern, snippet_part in expected:
        assert any(
            consumer.file == "src/com/example/RestHandler.java"
            and consumer.type == consumer_type
            and consumer.pattern == pattern
            and snippet_part in consumer.evidence[0].snippet
            for consumer in consumers
        ), (consumer_type, pattern, snippet_part)
    _assert_all_detections_have_evidence(consumers)
    _assert_unique_ids(consumers)


def test_detects_spring_get_mapping(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/main/java/example/ImportController.java": """
@RestController
class ImportController {
    @GetMapping(\"/imports\")
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert any(
        entrypoint.file == "src/main/java/example/ImportController.java"
        and entrypoint.method == "get"
        and entrypoint.route_path == "/imports"
        and _has_evidence(entrypoint, pattern="spring_mapping")
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_get_mapping_value_attribute(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
class ImportController {
    @GetMapping(value = \"/imports\")
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "get"
        and entrypoint.route_path == "/imports"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "controller.java"
    assert match.evidence[0].line == 4
    assert match.evidence[0].pattern == "spring_mapping"
    assert "@GetMapping" in match.evidence[0].snippet
    assert "value" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_post_mapping_path_attribute(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
class ImportController {
    @PostMapping(path = \"/imports\")
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/imports"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "controller.java"
    assert match.evidence[0].line == 4
    assert match.evidence[0].pattern == "spring_mapping"
    assert "@PostMapping" in match.evidence[0].snippet
    assert "path" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_request_mapping_path_and_method_attribute(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
class ImportController {
    @RequestMapping(path = \"/imports\", method = RequestMethod.POST)
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/imports"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "controller.java"
    assert match.evidence[0].line == 4
    assert match.evidence[0].pattern == "spring_mapping"
    assert "RequestMethod.POST" in match.evidence[0].snippet
    assert "path" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_request_mapping_method_before_value_attribute(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
class ImportController {
    @RequestMapping(method = RequestMethod.POST, value = \"/imports\")
    String imports() { return \"ok\"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/imports"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "controller.java"
    assert match.evidence[0].line == 4
    assert match.evidence[0].pattern == "spring_mapping"
    assert "RequestMethod.POST" in match.evidence[0].snippet
    assert "value" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_spring_mapping_outside_class_blocks(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "api.java": """
@RequestMapping("/api")
interface ReportApi {
    @GetMapping("/reports")
    List<Report> reports();
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    assert any(
        entrypoint.file == "api.java"
        and entrypoint.method == "get"
        and entrypoint.route_path == "/reports"
        and entrypoint.evidence[0].pattern == "spring_mapping"
        for entrypoint in entrypoints
    )
    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_enriches_spring_mapping_with_class_prefix_and_handler(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "src/main/java/example/ImportController.java": """
package example;

@RestController
@RequestMapping("/api")
class ImportController {
    @GetMapping("/imports")
    String imports() { return "ok"; }

    @PostMapping(path = "/imports")
    ResponseEntity<String> createImport() { return null; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    get_match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/java/example/ImportController.java"
        and entrypoint.method == "get"
        and entrypoint.route_path == "/api/imports"
    )
    assert get_match.handler == "ImportController#imports"
    assert get_match.evidence[0].pattern == "spring_mapping"

    post_match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "src/main/java/example/ImportController.java"
        and entrypoint.method == "post"
        and entrypoint.route_path == "/api/imports"
    )
    assert post_match.handler == "ImportController#createImport"
    assert post_match.evidence[0].pattern == "spring_mapping"

    assert not any(
        entrypoint.file == "src/main/java/example/ImportController.java"
        and entrypoint.method in {"get", "post"}
        and entrypoint.route_path == "/imports"
        for entrypoint in entrypoints
    )

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_enriches_spring_request_mapping_with_method_and_handler(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
@RequestMapping(path = "/admin")
class AdminController {
    @RequestMapping(path = "/reports", method = RequestMethod.DELETE)
    void deleteReport() {}
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "delete"
        and entrypoint.route_path == "/admin/reports"
    )
    assert match.handler == "AdminController#deleteReport"
    assert match.evidence[0].pattern == "spring_mapping"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_leaves_spring_dynamic_routes_unenriched(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "controller.java": """
@RestController
@RequestMapping(BASE_PATH)
class DynamicController {
    @GetMapping("/fixed")
    String fixed() { return "ok"; }

    @PostMapping(path = dynamicPath)
    String dynamic() { return "ok"; }
}
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    fixed = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "controller.java"
        and entrypoint.method == "get"
        and entrypoint.route_path == "/fixed"
    )
    assert fixed.handler == "DynamicController#fixed"

    assert not any(
        entrypoint.file == "controller.java" and entrypoint.handler == "DynamicController#dynamic"
        for entrypoint in entrypoints
    )

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_django_urlpatterns(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "urls.py": """
from django.urls import path
from . import views

urlpatterns = [
    path(\"preview/\", views.preview),
]
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "urls.py" and entrypoint.route_path == "preview/"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "urls.py"
    assert match.evidence[0].line == 6
    assert match.evidence[0].pattern == "django_urlpatterns"
    assert "path(" in match.evidence[0].snippet
    assert "preview/" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_detects_django_multiline_urlpatterns(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "urls.py": """
from django.urls import path
from . import views

urlpatterns = [
    path(
        \"preview/\",
        views.preview,
    ),
]
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "urls.py" and entrypoint.route_path == "preview/"
    )
    assert match.type == EntrypointType.HTTP_ROUTE
    assert match.line > 0
    assert match.evidence[0].file == "urls.py"
    assert match.evidence[0].line in {6, 7}
    assert match.evidence[0].pattern == "django_urlpatterns"
    assert "path(" in match.evidence[0].snippet or "preview/" in match.evidence[0].snippet
    _assert_all_detections_have_evidence(entrypoints)


def test_enriches_django_urlpatterns_with_simple_handlers(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "urls.py": """
from django.urls import path, re_path
from . import views

urlpatterns = [
    path("preview/", views.preview),
    re_path(r"^reports/$", reports.views.list_reports),
    path("class-view/", ReportView.as_view()),
]
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    preview = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "urls.py" and entrypoint.route_path == "preview/"
    )
    assert preview.handler == "views.preview"
    assert preview.evidence[0].pattern == "django_urlpatterns"

    reports = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "urls.py" and entrypoint.route_path == "^reports/$"
    )
    assert reports.handler == "reports.views.list_reports"
    assert reports.evidence[0].pattern == "django_urlpatterns"

    class_view = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "urls.py" and entrypoint.route_path == "class-view/"
    )
    assert class_view.handler == "ReportView.as_view()"
    assert class_view.evidence[0].pattern == "django_urlpatterns"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_enriches_multiline_django_urlpatterns_with_handler(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "urls.py": """
from django.urls import path
from . import views

urlpatterns = [
    path(
        "preview/",
        views.preview,
    ),
]
""",
        },
    )

    entrypoints = detect_entrypoints(repo_root, files)

    match = next(
        entrypoint
        for entrypoint in entrypoints
        if entrypoint.file == "urls.py" and entrypoint.route_path == "preview/"
    )
    assert match.handler == "views.preview"
    assert match.evidence[0].pattern == "django_urlpatterns"

    _assert_all_detections_have_evidence(entrypoints)
    _assert_unique_ids(entrypoints)



def test_detects_bare_process_worker(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"jobs/import.js": "const queue = require('./queue'); process('import', async job => job.data);\n"},
    )

    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)

    assert any(
        consumer.file == "jobs/import.js"
        and consumer.type == ConsumerType.QUEUE_OPERATION
        and consumer.pattern == "queue_operation"
        and _has_evidence(consumer, pattern="queue_operation", file="jobs/import.js")
        and "process(" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert any(
        worker.file == "jobs/import.js"
        and worker.pattern == "queue_process"
        and _has_evidence(worker, pattern="queue_process")
        and "process(" in worker.evidence[0].snippet
        for worker in workers
    )
    worker_file_pattern_pairs = [(worker.file, worker.pattern) for worker in workers]
    assert len(worker_file_pattern_pairs) == len(set(worker_file_pattern_pairs))
    _assert_all_detections_have_evidence([*consumers, *workers])


def test_does_not_treat_bare_process_as_queue_without_worker_context(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"src/service.js": "function run() { process(input); }\n"},
    )

    consumers = detect_consumers(repo_root, files)
    workers = detect_workers(repo_root, files)

    assert not any(
        consumer.file == "src/service.js"
        and consumer.type == ConsumerType.QUEUE_OPERATION
        and consumer.pattern == "queue_operation"
        and "process(" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    assert not any(
        worker.file == "src/service.js"
        and worker.type == WorkerType.QUEUE_WORKER
        and worker.pattern == "queue_process"
        and "process(" in worker.evidence[0].snippet
        for worker in workers
    )
    _assert_all_detections_have_evidence([*consumers, *workers])


def test_detects_generic_render_template_consumer(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"views.py": "def preview(request):\n    return render(request, 'preview.html')\n"},
    )

    consumers = detect_consumers(repo_root, files)

    assert any(
        consumer.file == "views.py"
        and consumer.type == ConsumerType.TEMPLATE_OPERATION
        and consumer.pattern == "template_operation"
        and "render(" in consumer.evidence[0].snippet
        for consumer in consumers
    )
    _assert_all_detections_have_evidence(consumers)


def test_entrypoint_tuning_excludes_generic_graphql(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"schema.ts": "const resolver = {};\nexport const Mutation = {};\nexport const Query = {};\n"},
    )
    config = AuditConfig()
    config.focus.detectors.entrypoints.exclude = {"generic_graphql"}

    entrypoints = detect_entrypoints(repo_root, files, config)

    assert not any(entrypoint.type == EntrypointType.GRAPHQL_RESOLVER for entrypoint in entrypoints)


def test_entrypoint_tuning_excludes_nextjs_api_routes(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"app/api/import/route.ts": "export async function POST() { return Response.json({ ok: true }); }\n"},
    )
    config = AuditConfig()
    config.focus.detectors.entrypoints.exclude = {"next_api_route"}

    entrypoints = detect_entrypoints(repo_root, files, config)

    assert not any(entrypoint.evidence[0].pattern == "next_api_route" for entrypoint in entrypoints)


def test_entrypoint_tuning_include_keeps_only_express_route(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"app.js": "app.post('/import', handler);\nfunction webhook(request) { return ok; }\n"},
    )
    config = AuditConfig()
    config.focus.detectors.entrypoints.include = {"express_route"}

    entrypoints = detect_entrypoints(repo_root, files, config)

    assert any(entrypoint.route_path == "/import" for entrypoint in entrypoints)
    assert all(entrypoint.evidence[0].pattern == "express_route" for entrypoint in entrypoints)


def test_consumer_tuning_excludes_network_operation_only(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {"main.py": "requests.get(url)\nopen(path)\n"},
    )
    config = AuditConfig()
    config.focus.detectors.consumers.exclude = {"network_operation"}

    consumers = detect_consumers(repo_root, files, config)

    assert any(consumer.type == ConsumerType.FILE_OPERATION for consumer in consumers)
    assert not any(consumer.type == ConsumerType.NETWORK_OPERATION for consumer in consumers)


def test_worker_tuning_include_keeps_only_taskengine(tmp_path):
    repo_root, files = _indexed_tmp_repo(
        tmp_path,
        {
            "conf/taskengine.xml": '<TaskEngine_Task task_name="export" class_name="ExportTask" />\n',
            "jobs/import.js": "const queue = require('./queue'); queue.process('import', async job => job.data);\n",
        },
    )
    config = AuditConfig()
    config.focus.detectors.workers.include = {"taskengine_task"}

    workers = detect_workers(repo_root, files, config)

    assert any(worker.pattern == "taskengine_task" for worker in workers)
    assert all(worker.pattern == "taskengine_task" for worker in workers)
