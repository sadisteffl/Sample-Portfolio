output "cluster_name" {
  description = "The name of the EKS cluster."
  value       = aws_eks_cluster.eks_cluster.name
}

output "kubeconfig_command" {
  description = "Command to configure kubectl for your EKS cluster."
  value       = "aws eks update-kubeconfig --name ${aws_eks_cluster.eks_cluster.name} --region us-east-1"
}


