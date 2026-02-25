use ratatui::{
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Cell, Row, Table},
};
use vta_sdk::client::{AddWebvhServerRequest, UpdateWebvhServerRequest, VtaClient};

use crate::render::print_widget;

pub async fn cmd_webvh_server_add(
    client: &VtaClient,
    id: String,
    did: String,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = AddWebvhServerRequest { id, did, label };
    let record = client.add_webvh_server(req).await?;
    println!("WebVH server added:");
    println!("  ID:  {}", record.id);
    println!("  DID: {}", record.did);
    if let Some(label) = &record.label {
        println!("  Label: {label}");
    }
    Ok(())
}

pub async fn cmd_webvh_server_list(
    client: &VtaClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.list_webvh_servers().await?;

    if resp.servers.is_empty() {
        println!("No WebVH servers configured.");
        return Ok(());
    }

    let header_style = Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD);
    let header = Row::new(vec!["ID", "DID", "Label", "Created"])
        .style(header_style)
        .bottom_margin(1);

    let rows: Vec<Row> = resp
        .servers
        .iter()
        .map(|s| {
            let label = s.label.clone().unwrap_or_else(|| "\u{2014}".into());
            let created = s.created_at.format("%Y-%m-%d %H:%M").to_string();

            Row::new(vec![
                Cell::from(s.id.clone()),
                Cell::from(s.did.clone()).style(Style::default().fg(Color::DarkGray)),
                Cell::from(label),
                Cell::from(created).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let title = format!(" WebVH Servers ({}) ", resp.servers.len());

    let table = Table::new(
        rows,
        [
            Constraint::Length(16), // ID
            Constraint::Min(40),   // DID
            Constraint::Min(16),   // Label
            Constraint::Length(18), // Created
        ],
    )
    .header(header)
    .column_spacing(2)
    .block(
        Block::bordered()
            .title(title)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    let height = resp.servers.len() as u16 + 4;
    print_widget(table, height);

    Ok(())
}

pub async fn cmd_webvh_server_update(
    client: &VtaClient,
    id: &str,
    label: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let req = UpdateWebvhServerRequest { label };
    let record = client.update_webvh_server(id, req).await?;
    println!("WebVH server updated:");
    println!("  ID:  {}", record.id);
    println!("  DID: {}", record.did);
    if let Some(label) = &record.label {
        println!("  Label: {label}");
    }
    Ok(())
}

pub async fn cmd_webvh_server_remove(
    client: &VtaClient,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    client.remove_webvh_server(id).await?;
    println!("WebVH server removed: {id}");
    Ok(())
}
