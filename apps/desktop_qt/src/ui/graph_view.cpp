#include "zara/desktop_qt/ui/graph_view.hpp"

#include <QBrush>
#include <QGraphicsItem>
#include <QGraphicsScene>
#include <QGraphicsTextItem>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPen>
#include <QRectF>
#include <QWheelEvent>

#include <algorithm>
#include <map>
#include <tuple>

namespace zara::desktop_qt::ui {

GraphView::GraphView(QString placeholder, QWidget* parent)
    : QGraphicsView(parent),
      placeholder_(std::move(placeholder)),
      scene_(new QGraphicsScene(this)) {
    setScene(scene_);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse);
    setResizeAnchor(QGraphicsView::AnchorUnderMouse);
    setFocusPolicy(Qt::StrongFocus);
    setCacheMode(QGraphicsView::CacheBackground);
    setRenderHint(QPainter::Antialiasing, true);
    setRenderHint(QPainter::TextAntialiasing, true);
    setViewportUpdateMode(QGraphicsView::BoundingRectViewportUpdate);
    show_placeholder();
}

void GraphView::set_node_activated_handler(std::function<void(const QString&)> handler) {
    node_activated_handler_ = std::move(handler);
}

void GraphView::show_placeholder(const QString& text) {
    resetTransform();
    scene_->clear();
    scene_->setBackgroundBrush(QBrush(QColor("#FAF9F4")));
    auto* item = scene_->addText(text.isEmpty() ? placeholder_ : text);
    item->setDefaultTextColor(QColor("#647073"));
    item->setPos(20.0, 16.0);
}

void GraphView::render_graph(const QString& title, const std::vector<GraphNode>& nodes, const std::vector<GraphEdge>& edges) {
    resetTransform();
    scene_->clear();
    scene_->setBackgroundBrush(QBrush(QColor("#FAF9F4")));

    auto* title_item = scene_->addText(title);
    title_item->setDefaultTextColor(QColor("#183A37"));
    title_item->setPos(20.0, 10.0);

    constexpr qreal node_width = 312.0;
    constexpr qreal node_height = 92.0;
    constexpr qreal margin_x = 34.0;
    constexpr qreal margin_y = 60.0;
    constexpr qreal layer_gap = 172.0;
    constexpr qreal row_gap = 44.0;

    std::map<QString, std::tuple<qreal, qreal, qreal, qreal>> positions;
    std::map<int, std::vector<const GraphNode*>> layered_nodes;
    for (const auto& node : nodes) {
        layered_nodes[node.layer].push_back(&node);
    }

    int max_rows = 1;
    for (auto& [layer, items] : layered_nodes) {
        std::sort(
            items.begin(),
            items.end(),
            [](const GraphNode* left, const GraphNode* right) {
                return std::tie(left->order, left->id) < std::tie(right->order, right->id);
            }
        );
        max_rows = std::max<int>(max_rows, static_cast<int>(items.size()));
    }

    const qreal column_height = (max_rows * node_height) + std::max(0, max_rows - 1) * row_gap;
    int column_index = 0;
    for (const auto& [layer, items] : layered_nodes) {
        Q_UNUSED(layer);
        const qreal local_height = (items.size() * node_height) + std::max<int>(0, static_cast<int>(items.size()) - 1) * row_gap;
        const qreal start_y = margin_y + std::max<qreal>(0.0, (column_height - local_height) / 2.0);
        const qreal x = margin_x + (column_index * (node_width + layer_gap));
        for (std::size_t row_index = 0; row_index < items.size(); ++row_index) {
            const qreal y = start_y + (static_cast<qreal>(row_index) * (node_height + row_gap));
            positions[items[row_index]->id] = std::make_tuple(x, y, node_width, node_height);
        }
        ++column_index;
    }

    for (const auto& node : nodes) {
        const auto position_it = positions.find(node.id);
        if (position_it == positions.end()) {
            continue;
        }

        const auto [x, y, width, height] = position_it->second;
        const QRectF rect(x, y, width, height);
        QPainterPath node_path;
        node_path.addRoundedRect(rect, 12.0, 12.0);
        QPen pen(node.border);
        pen.setWidthF(node.border_width);
        auto* node_item = scene_->addPath(node_path, pen, QBrush(node.fill));
        node_item->setData(0, node.id);

        auto* label_item = scene_->addText(node.label);
        label_item->setDefaultTextColor(node.label_color);
        label_item->setPos(x + 10.0, y + 8.0);
        label_item->setTextWidth(width - 20.0);
        label_item->setData(0, node.id);

        auto* detail_item = scene_->addText(node.detail);
        detail_item->setDefaultTextColor(node.detail_color);
        detail_item->setPos(x + 10.0, y + 36.0);
        detail_item->setTextWidth(width - 20.0);
        detail_item->setData(0, node.id);
    }

    for (const auto& edge : edges) {
        const auto source_it = positions.find(edge.source);
        const auto target_it = positions.find(edge.target);
        if (source_it == positions.end() || target_it == positions.end()) {
            continue;
        }

        const auto [sx, sy, sw, sh] = source_it->second;
        const auto [tx, ty, tw, th] = target_it->second;
        const qreal start_x = sx + sw;
        const qreal start_y = sy + (sh / 2.0);
        const qreal end_x = tx;
        const qreal end_y = ty + (th / 2.0);

        QPainterPath path;
        path.moveTo(start_x, start_y);
        if (tx >= sx) {
            qreal lane_x = std::min(end_x - 20.0, start_x + 52.0 + (edge.route_index * 12.0));
            if (lane_x <= start_x) {
                lane_x = start_x + 24.0;
            }
            path.lineTo(lane_x, start_y);
            if (std::abs(end_y - start_y) > 1.0) {
                path.lineTo(lane_x, end_y);
            }
            path.lineTo(end_x, end_y);
        } else {
            const qreal bridge_y = std::min(sy, ty) - 30.0 - (edge.route_index * 14.0);
            const qreal retreat_x = std::min(sx, tx) - 52.0 - (edge.route_index * 16.0);
            path.lineTo(start_x + 20.0, start_y);
            path.lineTo(start_x + 20.0, bridge_y);
            path.lineTo(retreat_x, bridge_y);
            path.lineTo(retreat_x, end_y);
            path.lineTo(end_x, end_y);
        }

        QPen pen(edge.color);
        pen.setWidthF(edge.width);
        pen.setStyle(edge.style);
        scene_->addPath(path, pen);

        if (!edge.label.isEmpty()) {
            auto* label_item = scene_->addText(edge.label);
            label_item->setDefaultTextColor(edge.label_color);
            label_item->setPos((start_x + end_x) / 2.0 - 18.0, std::min(start_y, end_y) - 24.0);
        }
    }

    const QRectF bounds = scene_->itemsBoundingRect().adjusted(-40.0, -24.0, 40.0, 40.0);
    scene_->setSceneRect(bounds);
    fit_scene_bounds(bounds);
    nudge_initial_zoom(bounds);
}

void GraphView::keyPressEvent(QKeyEvent* event) {
    switch (event->key()) {
        case Qt::Key_Plus:
        case Qt::Key_Equal:
            apply_zoom(1.18);
            event->accept();
            return;
        case Qt::Key_Minus:
        case Qt::Key_Underscore:
            apply_zoom(1.0 / 1.18);
            event->accept();
            return;
        case Qt::Key_0:
        case Qt::Key_F: {
            const QRectF bounds = scene_->itemsBoundingRect().adjusted(-40.0, -24.0, 40.0, 40.0);
            if (!bounds.isEmpty()) {
                fit_scene_bounds(bounds);
                nudge_initial_zoom(bounds);
            }
            event->accept();
            return;
        }
        default:
            break;
    }
    QGraphicsView::keyPressEvent(event);
}

void GraphView::wheelEvent(QWheelEvent* event) {
    if (event->angleDelta().y() == 0) {
        QGraphicsView::wheelEvent(event);
        return;
    }
    const qreal factor = event->angleDelta().y() > 0 ? 1.15 : (1.0 / 1.15);
    apply_zoom(factor);
    event->accept();
}

void GraphView::mousePressEvent(QMouseEvent* event) {
    if (node_activated_handler_) {
        if (auto* item = itemAt(event->pos()); item != nullptr) {
            const QVariant node_id = item->data(0);
            if (node_id.isValid()) {
                node_activated_handler_(node_id.toString());
            }
        }
    }
    QGraphicsView::mousePressEvent(event);
}

void GraphView::mouseDoubleClickEvent(QMouseEvent* event) {
    QGraphicsView::mouseDoubleClickEvent(event);
    const QRectF bounds = scene_->itemsBoundingRect().adjusted(-40.0, -24.0, 40.0, 40.0);
    if (!bounds.isEmpty()) {
        fit_scene_bounds(bounds);
        nudge_initial_zoom(bounds);
    }
}

void GraphView::apply_zoom(const qreal factor) {
    if (factor <= 0.0) {
        return;
    }

    const qreal current_scale = transform().m11();
    if (current_scale <= 0.0) {
        scale(factor, factor);
        return;
    }

    const qreal next_scale = current_scale * factor;
    if (next_scale < min_zoom_ || next_scale > max_zoom_) {
        return;
    }
    scale(factor, factor);
}

void GraphView::fit_scene_bounds(const QRectF& bounds) {
    if (bounds.isEmpty()) {
        return;
    }
    resetTransform();
    fitInView(bounds, Qt::KeepAspectRatio);
    centerOn(bounds.center());
}

void GraphView::nudge_initial_zoom(const QRectF& bounds) {
    if (bounds.isEmpty() || viewport() == nullptr) {
        return;
    }

    const qreal viewport_width = std::max<qreal>(1.0, viewport()->width());
    const qreal viewport_height = std::max<qreal>(1.0, viewport()->height());
    const qreal horizontal_pressure = bounds.width() / viewport_width;
    const qreal vertical_pressure = bounds.height() / viewport_height;

    qreal boost = 1.0;
    if (horizontal_pressure > 1.45) {
        boost = std::max(boost, std::min<qreal>(2.1, 1.0 + ((horizontal_pressure - 1.0) * 0.55)));
    }
    if (vertical_pressure > 1.15) {
        boost = std::max(boost, std::min<qreal>(1.45, 1.0 + ((vertical_pressure - 1.0) * 0.3)));
    }
    if (boost > 1.05) {
        apply_zoom(boost);
    }
}

}  // namespace zara::desktop_qt::ui
